"use client";

import { useEffect, useState } from "react";
import { InvoicePayment } from "@/components/invoice-payment";
import { BatchPayrollExecution } from "@/components/batch-payroll";
import { decodeBatchPayload, type ShareableBatchInvoice } from "@/lib/batch-payroll";

export function PayRouter({ encodedPayload }: { encodedPayload: string }) {
  const [isBatch, setIsBatch] = useState<boolean | null>(null);
  const [batchInvoice, setBatchInvoice] = useState<ShareableBatchInvoice | null>(null);

  useEffect(() => {
    decodeBatchPayload(encodedPayload)
      .then((res) => {
        if (res.status === "valid" || res.status === "expired") {
          setIsBatch(true);
          setBatchInvoice(res.invoice);
        } else {
          setIsBatch(false);
        }
      })
      .catch(() => {
        setIsBatch(false);
      });
  }, [encodedPayload]);

  if (isBatch === null) {
    return <div>Decoding payment payload...</div>;
  }

  if (isBatch && batchInvoice) {
    return <BatchPayrollExecution invoice={batchInvoice} />;
  }

  return <InvoicePayment encodedPayload={encodedPayload} />;
}
