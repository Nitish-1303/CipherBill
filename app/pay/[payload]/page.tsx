import { PayRouter } from "@/components/pay-router";

export default async function PayInvoicePage({ params }: Readonly<{ params: Promise<{ payload: string }> }>) {
  const { payload } = await params;
  return <PayRouter encodedPayload={payload} />;
}
