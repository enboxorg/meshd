export type MeshdDashboardURLContext = {
  ownerDID?: string;
  networkRecordID?: string;
};

function cleanParam(value: string | null): string | undefined {
  const cleaned = value?.trim();
  return cleaned || undefined;
}

export function dashboardContextFromSearch(search: string): MeshdDashboardURLContext {
  const params = new URLSearchParams(search);
  const ownerDID = cleanParam(params.get("owner"));
  const networkRecordID = cleanParam(params.get("network"));
  return {
    ...(ownerDID ? { ownerDID } : {}),
    ...(networkRecordID ? { networkRecordID } : {})
  };
}

export function ownerMatchesDashboardContext(context: MeshdDashboardURLContext, connectedDID?: string): boolean {
  return !context.ownerDID || context.ownerDID === connectedDID;
}
