const enc=new TextEncoder(),hx=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''),rnd=n=>hx(crypto.getRandomValues(new Uint8Array(n)));
async function hash(pw,salt){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);return hx(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:100000},k,256))}
const J=(d,h={})=>new Response(JSON.stringify(d),{headers:{'content-type':'application/json',...h}}),hexc=c=>/^#[0-9a-fA-F]{6}$/.test(c)?c:'#99aab5';
const MIME={png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',mp4:'video/mp4',webm:'video/webm',mp3:'audio/mpeg',ogg:'audio/ogg',wav:'audio/wav',pdf:'application/pdf',txt:'text/plain',zip:'application/zip'};
export async function onRequestPost({request,env,params}){
 if(request.headers.get('x-mc')!=='1')return J({err:'bad request'});
 const a=params.action,db=env.DB,B=(s,x)=>db.prepare(s).bind(...x),now=()=>Math.floor(Date.now()/1000);
 const all=async(s,...x)=>(await B(s,x).all()).results,one=(s,...x)=>B(s,x).first(),run=async(s,...x)=>(await B(s,x).run()).meta.last_row_id;
 const val=async(s,...x)=>{const r=await one(s,...x);return r?Object.values(r)[0]:null};
 let I={};if(a!='upload')try{I=await request.json()}catch{}
 const mem=async(s,u)=>!!await one('select 1 from members where server=? and user=?',s,u);
 const can=async(s,u,b)=>{if(await val('select owner from servers where id=?',s)==u)return true;let m=0;for(const r of await all('select r.perms p from roles r join member_roles m on m.role=r.id where r.server=? and m.user=?',s,u))m|=r.p;return !!(m&(b|1))};
 const acc=async(room,u)=>{room=String(room||'');const i=+room.slice(1);if(room[0]=='c'){const s=await val('select server from channels where id=?',i);return !!s&&await mem(s,u)}if(room[0]=='d')return !!await one('select 1 from dms where id=? and (a=? or b=?)',i,u,u);return false};
 const cookie=t=>({'set-cookie':`mc=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${t?2592000:0}`});
 const login=async id=>{const t=rnd(24);await run('insert into sessions values(?,?)',t,id);return J({ok:1},cookie(t))};
 const tok=((request.headers.get('cookie')||'').match(/mc=([0-9a-f]+)/)||[])[1];
 if(a=='register'){const n=(I.username||'').trim();if(!/^[A-Za-z0-9_]{2,20}$/.test(n))return J({err:'Username: 2-20 letters, numbers or _'});if((I.pw||'').length<6)return J({err:'Password needs 6+ characters'});
  if(await one('select 1 from users where username=?',n))return J({err:'Username taken'});
  const s=rnd(8);return login(await run('insert into users(username,pw,name) values(?,?,?)',n,s+':'+await hash(I.pw,s),n))}
 if(a=='login'){const r=await one('select * from users where username=?',I.username||'');if(!r)return J({err:'Wrong username or password'});const [s,h]=r.pw.split(':');
  if(await hash(I.pw||'',s)!==h)return J({err:'Wrong username or password'});return login(r.id)}
 if(a=='logout'){if(tok)await run('delete from sessions where token=?',tok);return J({ok:1},cookie(''))}
 const u=tok?await val('select user from sessions where token=?',tok):0;if(!u)return J({err:'auth'});
 const I_=(k,d='')=>I[k]??d,num=k=>+I[k]||0,ok=J({ok:1}),no=e=>J({err:e});
 switch(a){
 case 'boot':return J({me:await one('select id,username,name,bio,color,avatar from users where id=?',u),
  servers:await all('select s.id,s.name from servers s join members m on m.server=s.id where m.user=?',u),
  friends:await all('select f.a,f.ok,u.id uid,u.name,u.username,u.color from friends f join users u on u.id=(case when f.a=? then f.b else f.a end) where f.a=? or f.b=?',u,u,u),
  dms:await all('select d.id,u.name,u.color from dms d join users u on u.id=(case when d.a=? then d.b else d.a end) where d.a=? or d.b=?',u,u,u)});
 case 'srv':{const s=num('id');if(!await mem(s,u))return no('not a member');const sv=await one('select * from servers where id=?',s),mr={};
  for(const r of await all('select m.user,r.id,r.name,r.color from member_roles m join roles r on r.id=m.role where r.server=?',s))(mr[r.user]??=[]).push(r);
  const ms=await all('select u.id,u.name,u.color,u.bio,u.avatar from members m join users u on u.id=m.user where m.server=?',s);ms.forEach(m=>m.roles=mr[m.id]||[]);
  const k=await can(s,u,8);return J({id:s,name:sv.name,owner:sv.owner,invite:sv.invite,channels:await all('select id,name,type from channels where server=? order by id',s),members:ms,
   roles:await all('select id,name,color,perms from roles where server=?',s),bans:k?await all('select u.id,u.name from bans b join users u on u.id=b.user where b.server=?',s):[],
   can:{channels:await can(s,u,2),roles:await can(s,u,4),kick:k}})}
 case 'mkserver':{const n=I_('name').trim();if(!n)return no('Name required');const id=await run('insert into servers(name,owner,invite) values(?,?,?)',n.slice(0,40),u,rnd(4));
  await db.batch([B('insert into members values(?,?)',[id,u]),B("insert into channels(server,name,type) values(?,'general','text'),(?,'General','voice')",[id,id])]);return J({id})}
 case 'join':{const s=await val('select id from servers where invite=?',I_('code').trim());if(!s)return no('Invalid invite');if(await one('select 1 from bans where server=? and user=?',s,u))return no('You are banned from this server');
  await run('insert or ignore into members values(?,?)',s,u);return J({id:s})}
 case 'leave':await run('delete from members where server=? and user=?',num('id'),u);return ok;
 case 'mkchan':{const s=num('server');if(!await can(s,u,2))return no('Missing permission');
  const n=I_('name').toLowerCase().replace(/[^a-z0-9_ -]/g,'').replace(/ /g,'-').slice(0,30)||'new';await run('insert into channels(server,name,type) values(?,?,?)',s,n,I.type=='voice'?'voice':'text');return ok}
 case 'rmchan':{const s=await val('select server from channels where id=?',num('id'));if(!s||!await can(s,u,2))return no('Missing permission');
  await db.batch([B('delete from channels where id=?',[num('id')]),B('delete from messages where room=?',['c'+num('id')])]);return ok}
 case 'mkrole':{const s=num('server');if(!await can(s,u,4))return no('Missing permission');await run('insert into roles(server,name,color,perms) values(?,?,?,?)',s,I_('name','role').slice(0,30),hexc(I_('color')),num('perms')&31);return ok}
 case 'togrole':{const r=await one('select * from roles where id=?',num('role'));if(!r||!await can(r.server,u,4))return no('Missing permission');const t=num('user');if(!await mem(r.server,t))return no('Not a member');
  if(await one('select 1 from member_roles where role=? and user=?',r.id,t))await run('delete from member_roles where role=? and user=?',r.id,t);else await run('insert into member_roles values(?,?)',r.id,t);return ok}
 case 'kick':case 'ban':{const s=num('server'),t=num('user');if(!await can(s,u,8)||await val('select owner from servers where id=?',s)==t)return no('Not allowed');
  if(a=='ban')await run('insert or ignore into bans values(?,?)',s,t);await run('delete from members where server=? and user=?',s,t);return ok}
 case 'unban':{const s=num('server');if(!await can(s,u,8))return no('Not allowed');await run('delete from bans where server=? and user=?',s,num('user'));return ok}
 case 'msgs':{const rm=I_('room');if(!await acc(rm,u))return no('no access');
  const rows=(await all('select m.id,m.body,m.ts,m.user,m.file,m.edited,u.name,u.color,u.avatar from messages m join users u on u.id=m.user where room=? order by m.id desc limit 60',rm)).reverse(),re={};
  for(const r of await all('select msg,emo,count(*) n,max(user=?) me from reacts where msg in (select id from (select id from messages where room=? order by id desc limit 60)) group by msg,emo',u,rm))(re[r.msg]??=[]).push({emo:r.emo,n:r.n,me:r.me});
  rows.forEach(r=>r.re=re[r.id]||[]);return J(rows)}
 case 'send':{const b=I_('body').trim(),f=/^uploads\/[0-9a-f]{16}\.[a-z0-9]+$/.test(I_('file'))?I.file:null;if(!await acc(I_('room'),u)||(!b&&!f))return no('cannot send');
  await run('insert into messages(room,user,body,ts,file) values(?,?,?,?,?)',I.room,u,b.slice(0,2000),now(),f);return ok}
 case 'upload':{const f=(await request.formData()).get('f');if(!f||!f.size||f.size>8e6)return no('File missing or over 8 MB');
  const e=(f.name.split('.').pop()||'').toLowerCase();if(!MIME[e])return no('File type not allowed');const n=rnd(8)+'.'+e;
  await env.FILES.put(n,f.stream(),{httpMetadata:{contentType:MIME[e]}});return J({file:'uploads/'+n})}
 case 'edit':{const m=await one('select * from messages where id=?',num('id')),b=I_('body').trim();if(!m||m.user!=u||!b)return no('cannot edit');await run('update messages set body=?,edited=1 where id=?',b.slice(0,2000),m.id);return ok}
 case 'rmmsg':{const m=await one('select * from messages where id=?',num('id'));if(!m)return no('gone');let k=m.user==u;
  if(!k&&m.room[0]=='c'){const s=await val('select server from channels where id=?',+m.room.slice(1));k=!!s&&await can(s,u,16)}
  if(!k)return no('Not allowed');await db.batch([B('delete from messages where id=?',[m.id]),B('delete from reacts where msg=?',[m.id])]);return ok}
 case 'react':{const rm=await val('select room from messages where id=?',num('id')),e=I_('emo');if(!rm||!await acc(rm,u)||!['👍','❤️','😂'].includes(e))return no('no access');
  if(await one('select 1 from reacts where msg=? and user=? and emo=?',num('id'),u,e))await run('delete from reacts where msg=? and user=? and emo=?',num('id'),u,e);else await run('insert into reacts values(?,?,?)',num('id'),u,e);return ok}
 case 'addfriend':{const t=await val('select id from users where username=?',I_('username').trim());if(!t||t==u)return no('User not found');
  if(await one('select 1 from friends where a=? and b=?',t,u))await run('update friends set ok=1 where a=? and b=?',t,u);else await run('insert or ignore into friends(a,b) values(?,?)',u,t);return ok}
 case 'fresp':{const t=num('uid');if(I.accept)await run('update friends set ok=1 where a=? and b=?',t,u);else await run('delete from friends where (a=? and b=?) or (a=? and b=?)',t,u,u,t);return ok}
 case 'opendm':{const t=num('uid');if(t==u||!await one('select 1 from users where id=?',t))return no('bad user');
  let d=await val('select id from dms where (a=? and b=?) or (a=? and b=?)',u,t,t,u);if(!d)d=await run('insert into dms(a,b) values(?,?)',u,t);return J({id:d})}
 case 'profile':{const av=/^uploads\/[0-9a-f]{16}\.(png|jpe?g|gif|webp)$/.test(I_('avatar'))?I.avatar:null;
  await run('update users set name=?,bio=?,color=?,avatar=coalesce(?,avatar) where id=?',I_('name').trim().slice(0,32)||'user',I_('bio').slice(0,200),hexc(I_('color')),av,u);return ok}
 case 'vjoin':if(!await acc(I_('room'),u))return no('no access');await run('insert or replace into vpres values(?,?,?)',I.room,u,now());return ok;
 case 'vleave':await db.batch([B('delete from vpres where room=? and user=?',[I_('room'),u]),B('delete from vsig where too=?',[u])]);return ok;
 case 'vpoll':{const rm=I_('room');if(!await acc(rm,u))return no('no access');await run('insert or replace into vpres values(?,?,?)',rm,u,now());
  const peers=await all('select p.user id,u.name from vpres p join users u on u.id=p.user where p.room=? and p.ts>?',rm,now()-8),sigs=await all('select id,frm,data from vsig where room=? and too=? order by id',rm,u);
  if(sigs.length)await run('delete from vsig where room=? and too=? and id<=?',rm,u,sigs.at(-1).id);return J({peers,sigs})}
 case 'vsig':if(!await acc(I_('room'),u))return no('no access');await run('insert into vsig(room,frm,too,data) values(?,?,?,?)',I.room,u,num('to'),String(I_('data')));return ok;
 }
 return no('unknown action');
}
