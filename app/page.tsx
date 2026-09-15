import Dashboard from './dashboard';
import { getDashboardService } from '@/lib/data/service';
export const dynamic = 'force-dynamic';
export default async function Home() {
 const service = await getDashboardService();
 return <Dashboard data={await service.getDashboard()} />;
}
