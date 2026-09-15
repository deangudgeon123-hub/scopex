export function getSupabaseConfig() {
 const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
 const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
 if (!url || !key) throw new Error('Supabase configuration is missing. Set the project URL and publishable key.');
 const parsed = new URL(url);
 if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid Supabase URL.');
 return { url, key };
}
export function getDataMode(): 'demo' | 'supabase' {
 const mode = process.env.SCOPEX_DATA_MODE ?? 'demo';
 if (mode !== 'demo' && mode !== 'supabase') throw new Error('SCOPEX_DATA_MODE must be demo or supabase.');
 return mode;
}
