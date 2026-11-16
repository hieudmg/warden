import { SetupClient } from './setup'
import { mountSetup } from './setup-view'

mountSetup(document.getElementById('setup')!,new SetupClient())
