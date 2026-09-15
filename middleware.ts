import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';
import { getDataMode, getSupabaseConfig } from '@/lib/supabase/config';
export async function middleware(request: NextRequest) {
 if (getDataMode() === 'demo') return NextResponse.next();
 // The page/API reports missing configuration through its normal error boundary.
 if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) return NextResponse.next();
 const { url, key } = getSupabaseConfig();
 let response = NextResponse.next({ request });
 const supabase = createServerClient(url, key, { cookies: {
  getAll: () => request.cookies.getAll(),
  setAll(values) {
   values.forEach(({ name, value }) => request.cookies.set(name, value));
   response = NextResponse.next({ request });
   values.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
  },
 } });
 await supabase.auth.getUser();
 response.headers.set('Cache-Control', 'private, no-store');
 return response;
}
export const config = { matcher: ['/', '/api/:path*'] };
