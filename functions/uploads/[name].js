export async function onRequestGet({env,params}){
 const o=await env.FILES.get(params.name);if(!o)return new Response('Not found',{status:404});
 return new Response(o.body,{headers:{'content-type':o.httpMetadata?.contentType||'application/octet-stream','x-content-type-options':'nosniff','cache-control':'public, max-age=31536000, immutable'}})}
