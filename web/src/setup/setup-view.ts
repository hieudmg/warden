interface SetupActions {authorize(password:string):Promise<void>;register():Promise<string>;confirm(saved:string):Promise<void>;cancel():void}

// This entrypoint deliberately has no management-app imports or SPA router.
export function mountSetup(root:HTMLElement,client:SetupActions) {
 let ended=false
 const clear=()=>root.replaceChildren()
 const heading=(message:string)=>{const h=document.createElement('h1');h.textContent=message;root.append(h)}
 const paragraph=(message:string)=>{const p=document.createElement('p');p.textContent=message;root.append(p);return p}
 const error=(cause:unknown)=>{const p=paragraph(cause instanceof Error?cause.message:'Setup failed');p.setAttribute('role','alert')}
 const cancel=()=>{ended=true;client.cancel();clear();heading('Setup cancelled');paragraph('Stop and rerun warden-server init. No initialized marker is created before recovery confirmation.')}
 const cancelButton=()=>{const b=document.createElement('button');b.textContent='Cancel setup';b.onclick=cancel;root.append(b)}
 const form=(label:string,action:(value:string)=>Promise<void>)=>{
  const f=document.createElement('form'),l=document.createElement('label'),input=document.createElement('input'),button=document.createElement('button')
  l.textContent=label;input.type='password';input.autocomplete='off';input.required=true;l.append(input);button.textContent='Continue';button.type='submit';f.append(l,button);root.append(f)
  f.onsubmit=async e=>{e.preventDefault();if(button.disabled)return;button.disabled=true;const value=input.value;input.value='';try{await action(value)}catch(cause){if(!ended)error(cause)}finally{button.disabled=false}}
 }
 const confirm=()=>{clear();heading('Prove your saved recovery key');paragraph('Re-enter the complete key from your protected offline copy. A checkbox is not sufficient. Losing every passkey and this key loses vault access.')
  form('Saved recovery key',async value=>{await client.confirm(value);if(ended)return;ended=true;clear();heading('Warden initialized');paragraph('The temporary setup server has exited. This T1 milestone intentionally leaves normal serve disabled until T2; management is not available yet.')});cancelButton()}
 const register=()=>{clear();heading('Register the owner passkey');paragraph('User verification and WebAuthn PRF are required. Two authenticator prompts are expected. Unsupported PRF fails without committing storage.')
  const b=document.createElement('button');b.textContent='Register and verify passkey';root.append(b)
  b.onclick=async()=>{b.disabled=true;try{const recovery=await client.register();if(ended)return;clear();heading('Save your offline recovery key');paragraph('This is a plaintext offline secret. Save it privately, not in sync/shared folders. Do not navigate away before confirmation.');const pre=document.createElement('pre');pre.textContent=recovery;root.append(pre);const saved=document.createElement('button');saved.textContent='I saved it — hide and re-enter';saved.onclick=confirm;root.append(saved);cancelButton()}catch(cause){if(!ended)error(cause)}};cancelButton()}
 clear();heading('Initialize Warden');paragraph('Setup only. Enter the eight-character password shown on the controlling terminal. The fixed 15-minute lifetime cannot be extended.')
 form('Setup password',async value=>{await client.authorize(value);if(!ended)register()});cancelButton()
 window.addEventListener('pagehide',()=>{ended=true;client.cancel();clear()},{once:true})
}
