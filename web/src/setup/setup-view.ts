interface SetupActions {
 authorize(password:string):Promise<void>
 authenticationMethod?(): 'account'|'passkey'
 register():Promise<string>
 registerAccount?(username:string,password:string,confirmation:string):Promise<string>
 confirm(saved:string):Promise<void>
 cancel():void
}

// Setup has no management-app imports, router, or persisted secret form state.
export function mountSetup(root:HTMLElement,client:SetupActions) {
 let ended=false
 const clear=()=>root.replaceChildren()
 const heading=(message:string,step=1)=>{
  const badge=document.createElement('p');badge.className='eyebrow';badge.textContent=`WARDEN · PRIVATE SETUP · STEP ${step} OF 3`;root.append(badge)
  const h=document.createElement('h1');h.textContent=message;root.append(h)
 }
 const paragraph=(message:string)=>{const p=document.createElement('p');p.textContent=message;root.append(p);return p}
 const error=(cause:unknown)=>{root.querySelector('[role="alert"]')?.remove();const p=paragraph(cause instanceof Error?cause.message:'Setup failed');p.setAttribute('role','alert')}
 const cancel=()=>{ended=true;client.cancel();clear();heading('Setup cancelled');paragraph('Stop and rerun warden-server init. Nothing is initialized before recovery confirmation.')}
 const cancelButton=()=>{const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent='Cancel setup';b.onclick=cancel;root.append(b)}
 const field=(f:HTMLFormElement,label:string,name:string,type='password',autocomplete='off')=>{
  const l=document.createElement('label'),input=document.createElement('input');l.textContent=label;input.name=name;input.type=type;input.autocomplete=autocomplete as AutoFill;input.required=true;l.append(input);f.append(l);return input
 }
 const form=(label:string,action:(value:string)=>Promise<void>)=>{
  const f=document.createElement('form');root.append(f);const input=field(f,label,'secret'),button=document.createElement('button');button.textContent='Continue';button.type='submit';f.append(button)
  f.onsubmit=async e=>{e.preventDefault();if(button.disabled)return;button.disabled=true;const value=input.value;input.value='';try{await action(value)}catch(cause){if(!ended)error(cause)}finally{button.disabled=false}}
 }
 const confirm=()=>{clear();heading('Prove your saved recovery key',3);paragraph('Re-enter the complete key from your protected offline copy. Losing both your login credential and this key loses vault access.')
  form('Saved recovery key',async value=>{await client.confirm(value);if(ended)return;ended=true;clear();heading('Warden initialized',3);paragraph('Your owner credential and encrypted vault are ready. The temporary setup server has exited. Start warden-server serve with the same config, then sign in. Restart always starts locked.')});cancelButton()}
 const saved=(recovery:string)=>{if(ended)return;clear();heading('Save your offline recovery key',3);paragraph('This key can replace your login credential. Save it privately offline, never in shared or synchronized folders. It is shown only until you continue.');const pre=document.createElement('pre');pre.textContent=recovery;root.append(pre);const b=document.createElement('button');b.textContent='I saved it — hide and re-enter';b.onclick=confirm;root.append(b);cancelButton()}
 const register=()=>{clear();heading('Register the owner passkey',2);paragraph('Selected in the terminal: passkey. User verification and WebAuthn PRF are required. Two authenticator prompts are expected. Unsupported PRF fails without committing storage.')
  const b=document.createElement('button');b.textContent='Register and verify passkey';root.append(b)
  b.onclick=async()=>{b.disabled=true;try{saved(await client.register())}catch(cause){if(!ended)error(cause)}finally{b.disabled=false}};cancelButton()}
 const account=()=>{clear();heading('Create your owner account',2);paragraph('Selected in the terminal: account. Your password protects the vault key; it is not saved in setup answers. There is one personal owner, not a multi-account service.')
  paragraph('Choose a unique password of 12–1024 UTF-8 bytes. Spaces are preserved exactly. Keep it in a private password manager. You will re-enter it for sensitive actions.')
  const f=document.createElement('form');root.append(f)
  const username=field(f,'Username','username','text','username');username.maxLength=64
  const password=field(f,'Password','password','password','new-password'),confirmation=field(f,'Confirm password','password_confirmation','password','new-password')
  const b=document.createElement('button');b.type='submit';b.textContent='Create account and recovery key';f.append(b)
  f.onsubmit=async e=>{e.preventDefault();if(b.disabled)return;b.disabled=true;const name=username.value,p=password.value,c=confirmation.value;password.value='';confirmation.value='';try{if(!client.registerAccount)throw Error('Account setup unavailable');saved(await client.registerAccount(name,p,c))}catch(cause){if(!ended)error(cause)}finally{b.disabled=false}};cancelButton()
 }
 clear();heading('Initialize Warden');paragraph('A private home for your connections and secrets. This temporary HTTPS page can only initialize fresh storage; it cannot access management data.')
 paragraph('Enter the eight-character password shown on the controlling terminal. The fixed 15-minute setup window cannot be extended. Authentication method is chosen in warden-server init, not by this page.')
 form('Setup password',async value=>{await client.authorize(value);if(!ended){if(client.authenticationMethod?.()==='account')account();else register()}});cancelButton()
 window.addEventListener('pagehide',()=>{ended=true;client.cancel();clear()},{once:true})
}
