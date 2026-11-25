"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";
import { EmptyState, Loading, PageHeader } from "@/components/ui";
import { usePoll, type Experiment } from "@/lib/api";

/** Results now live on each experiment's page. Old links land on the right experiment. */
function Redirect() {
  const router = useRouter();
  const wanted = useSearchParams().get("experiment");
  const experiments = usePoll<Experiment[]>(wanted ? null : "/experiments");
  const target = wanted ?? experiments.data?.find((e) => e.status === "completed")?.id ?? null;
  useEffect(() => {
    if (target) router.replace(`/experiments/${target}`);
  }, [router, target]);
  if (!wanted && experiments.data && !target) {
    return (
      <>
        <PageHeader title="Results" />
        <EmptyState title="No completed experiments"><Link href="/experiments" className="underline">Run an experiment</Link> first.</EmptyState>
      </>
    );
  }
  return <Loading />;
}

export default function AnalyticsPage() {
  return <Suspense fallback={<Loading />}><Redirect /></Suspense>;
}
