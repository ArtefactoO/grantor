// Capture synthetic API fixtures in the real frontend. No live login or target operations.
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.DEMO_URL || 'http://127.0.0.1:4187';
if (!['127.0.0.1', 'localhost'].includes(new URL(base).hostname)) throw Error('Use a loopback preview');
const output = process.env.DEMO_OUTPUT;
if (!output) throw Error('Set DEMO_OUTPUT');
fs.mkdirSync(output, {recursive:true});
async function run(setup, story) {
 const browser = await chromium.launch({headless:true, executablePath:process.env.CHROMIUM_EXECUTABLE_PATH || undefined, args:['--no-sandbox']});
 try {
  const context = await browser.newContext({viewport:{width:1360,height:860},colorScheme:'dark',reducedMotion:'reduce'});
  await context.route('**/*', r => r.request().url().startsWith(base + '/') ? r.continue() : r.abort());
  await setup(context);
  const page = await context.newPage(), errors = [];
  page.on('pageerror', e => errors.push(e.message));
  let n = 0;
  const frame = async () => {await page.waitForTimeout(650); await page.screenshot({path:path.join(output, String(n++).padStart(2,'0')+'.png')});};
  await story(page, frame);
  fs.writeFileSync(path.join(output,'capture.json'), JSON.stringify({frames:n,errors},null,2));
  if(errors.length) throw Error(errors.join('\n'));
 } finally { await browser.close(); }
}
const now = new Date().toISOString();
const connections = [
 ['postgres','Orders PostgreSQL','orders-db.demo.internal:5432','16.4'],
 ['kafka','Event stream','broker.demo.internal:9092','3.9'],
 ['clickhouse','Analytics','analytics.demo.internal:8123','25.1'],
 ['redis','Application cache','cache.demo.internal:6379','7.4'],
 ['rabbitmq','Task queue','queue.demo.internal:15672','4.0'],
].map(([engine,display_name,endpoint,server_version],i)=>({id:`00000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`,engine,display_name,environment:'demo',tags:[],endpoints:[endpoint],execution_mode:'direct',tls_config:{},admin_credential_mode:'vault',vault_admin_path:'demo/credentials',capabilities:[],discovery_config:{},status:'active',server_version,topology:{},last_discovery_at:now,created_at:now,updated_at:now,drift:{status:'in_sync',added:0,removed:0,changed:0}}));
run(async context=>{
 await context.addInitScript(()=>{localStorage.setItem('grantor-theme','dark');});
 await context.route('**/auth/me',r=>r.fulfill({json:{email:'demo@example.test',role:'admin',csrf_token:'synthetic-ui-fixture',csrf_header:'X-Grantor-CSRF'}}));
 await context.route('**/api/v1/**',r=>{
  const p=new URL(r.request().url()).pathname;
  let data={};
  if(p==='/api/v1/connections')data={connections};
  else if(p==='/api/v1/environments')data={environments:[{id:'demo',name:'demo',display_name:'Demo',status:'active'}]};
  else if(p==='/api/v1/engines')data={engines:['postgres','kafka','clickhouse','redis','rabbitmq']};
  else if(p.startsWith('/api/v1/operations'))data={operations:[],total:0};
  else if(p==='/api/v1/runtime-config')data={};
  else if(p==='/api/v1/principals')data={principals:[]};
  else if(p.endsWith('/resources'))data={resources:[]};
  else if(p.endsWith('/accounts'))data={accounts:['app_api','report_reader','batch_worker'].map((name,i)=>({id:'demo-account-'+i,principal_id:null,connection_id:connections[0].id,kind:'login',engine_identity:name,authentication_scope:'',credential_mode:null,vault_path:'',status:'active',ownership:'unmanaged',attributes:{},created_at:now,updated_at:now,bindings:[]}))};
  else if(p.endsWith('/role-policies'))data={policies:[]};
  else if(p.endsWith('/favorites'))data={connection_ids:[]};
  else {const c=connections.find(c=>p==='/api/v1/connections/'+c.id);if(c)data=c;}
  return r.fulfill({json:data});
 });
},async(page,frame)=>{
 await page.goto(base+'/');await page.getByRole('textbox',{name:'Поиск подключений'}).waitFor();await frame();
 const search=page.getByRole('textbox',{name:'Поиск подключений'});await search.fill('PostgreSQL');await frame();
 await page.locator('a:visible').filter({hasText:'Orders PostgreSQL'}).first().click();await frame();
 await page.goto(base+'/');await page.getByRole('textbox',{name:'Поиск подключений'}).fill('');await frame();
}).catch(e=>{console.error(e);process.exitCode=1;});
