-- Flows of one conversation, oldest first (Connections > flows dialog, Save PCAP per flow):
-- `conversation_flows_page` filters on (src_ip, dst_ip) and pages by (first_ts, id). Range 0400-0499.
CREATE INDEX flows_conversation ON flows (src_ip, dst_ip, first_ts);
