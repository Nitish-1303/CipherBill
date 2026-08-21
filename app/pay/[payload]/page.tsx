import { InvoicePayment } from "@/components/invoice-payment";

export default async function PayInvoicePage({ params }: Readonly<{ params: Promise<{ payload: string }> }>) {
  const { payload } = await params;
  return <InvoicePayment encodedPayload={payload} />;
}
