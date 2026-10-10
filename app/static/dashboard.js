'use strict';
const $ = id => document.getElementById(id);
let offset = 0, generation = 0, detailGeneration = 0;
const limit = 10, charts = [];
async function get(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`请求失败 (${response.status})`);
  return response.json();
}
function chart(id, option) {
  const instance = echarts.getInstanceByDom($(id)) || echarts.init($(id));
  if (!charts.includes(instance)) charts.push(instance);
  instance.setOption({...option, color:['#168077','#466fba','#d5a24b'], aria:{enabled:true}}, true);
}
async function detail(id) {
  const version = ++detailGeneration;
  $('detail').hidden = false; $('detail-title').textContent = `告警 #${id} · 加载中…`;
  $('event-details').textContent = '';
  try {
    const data = await get(`/api/alerts/${id}`);
    if (version !== detailGeneration) return;
    $('detail-title').textContent = `告警 #${id} · ${data.alert.fingerprint} · ${data.events.length} 个关联事件`;
    $('event-details').textContent = data.events.map(e => `事件 #${e.id} · ${e.timestamp} · ${e.source_type} · ${e.result}\n${e.raw_log}`).join('\n\n') || '无关联事件';
    $('detail').scrollIntoView({behavior:'smooth',block:'nearest'});
  } catch (error) { if (version === detailGeneration) $('detail-title').textContent = error.message; }
}
async function refresh() {
  const version = ++generation;
  $('message').textContent = '正在加载…';
  $('previous').disabled = true; $('next').disabled = true;
  const query = new URLSearchParams({limit,offset});
  if ($('status').value) query.set('status',$('status').value);
  try {
    const [summary,trend,sources,rules,alerts] = await Promise.all([
      get('/api/statistics/summary'),get('/api/statistics/trend'),get('/api/statistics/sources'),
      get('/api/statistics/rules'),get(`/api/alerts?${query}`)]);
    if (version !== generation) return;
    $('total').textContent=summary.total_alerts; $('open').textContent=summary.open_alerts; $('confirmed').textContent=summary.confirmed_alerts;
    $('alerts').replaceChildren();
    for (const a of alerts.items) {
      const row=document.createElement('tr');
      for (const value of [a.id,a.source_ip,a.rule_type,a.status,a.occurrence_count,a.last_seen]) {
        const cell=document.createElement('td'); cell.textContent=value; row.append(cell);
      }
      const cell=document.createElement('td'), button=document.createElement('button');
      button.textContent='查看事件'; button.addEventListener('click',()=>detail(a.id)); cell.append(button); row.append(cell); $('alerts').append(row);
    }
    if (!alerts.items.length) {
      const row=document.createElement('tr'),cell=document.createElement('td'); cell.colSpan=7;cell.textContent='暂无符合条件的告警';row.append(cell);$('alerts').append(row);
    }
    $('page').textContent=`共 ${alerts.total} 条 · 第 ${Math.floor(offset/limit)+1} 页`;
    $('previous').disabled=offset===0; $('next').disabled=offset+limit>=alerts.total;
    if (!window.echarts) { $('message').textContent='数据已加载，图表库加载失败，请检查 CDN 网络后重新加载页面。'; return; }
    chart('trend',{tooltip:{trigger:'axis',renderMode:'richText'},grid:{left:45,right:25,bottom:35},xAxis:{type:'category',data:trend.map(x=>x.date)},yAxis:{type:'value',minInterval:1},series:[{type:'line',data:trend.map(x=>x.count),areaStyle:{opacity:.1}}]});
    chart('sources',{tooltip:{trigger:'axis',renderMode:'richText'},grid:{left:130,right:25,bottom:30},xAxis:{type:'value',minInterval:1},yAxis:{type:'category',inverse:true,data:sources.map(x=>x.source_ip)},series:[{type:'bar',data:sources.map(x=>x.count)}],title:sources.length?undefined:{text:'暂无告警',left:'center',top:'center',textStyle:{fontSize:14,color:'#63758a'}}});
    chart('rules',{tooltip:{trigger:'item',renderMode:'richText'},legend:{bottom:0},series:[{type:'pie',radius:['40%','65%'],label:{show:false},data:rules.map(x=>({name:x.rule_type,value:x.count}))}],title:rules.length?undefined:{text:'暂无告警',left:'center',top:'center',textStyle:{fontSize:14,color:'#63758a'}}});
    $('message').textContent='数据已更新 · '+new Date().toLocaleTimeString();
  } catch (error) { if(version===generation) $('message').textContent=`加载失败：${error.message}。可点击刷新重试。`; }
}
$('refresh').addEventListener('click',refresh);
$('status').addEventListener('change',()=>{offset=0;refresh();});
$('previous').addEventListener('click',()=>{offset=Math.max(0,offset-limit);refresh();});
$('next').addEventListener('click',()=>{offset+=limit;refresh();});
window.addEventListener('resize',()=>charts.forEach(c=>c.resize()));
refresh();
