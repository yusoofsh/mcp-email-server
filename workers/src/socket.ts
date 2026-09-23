import { connect } from "cloudflare:sockets";
import type { Connector } from "./wire";
export const connector: Connector = (hostname, port, secureTransport) =>
  connect({ hostname, port }, { secureTransport, allowHalfOpen: false });
