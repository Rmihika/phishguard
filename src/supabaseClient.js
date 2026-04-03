import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://zjfuosrpvpiswxmhfxpr.supabase.co'
const supabaseKey = 'sb_publishable_k0bXILKUSe-huuY8naCyAQ_oX8IQVV3'

export const supabase = createClient(supabaseUrl, supabaseKey)