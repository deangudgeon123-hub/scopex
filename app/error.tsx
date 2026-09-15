'use client';
export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
 return <main className="app-shell"><section className="foundation-state panel" role="alert"><span className="section-kicker">SCOPEX</span><h1>Your overview couldn’t be loaded.</h1><p>Please try again. In workspace mode, a signed-in account and a configured database are required.</p><button className="primary-button" onClick={reset}>Try again</button></section></main>;
}
