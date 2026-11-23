//! Translation of the `mqtt` analyzer's records into `mqtt_connections`, `mqtt_packets`,
//! `mqtt_topic_flows` and `mqtt_subscriptions` rows (the store moves the password apart).

use netsift_analyze::dissect::mqtt::Version;
use netsift_analyze::mqtt::{
    AckState, AuthKind, Dir, Login, MqttConnection, MqttPacket, MqttRecord, MqttSubscription,
    MqttTopicStat, TopicSource,
};
use netsift_store::mqtt::{
    MqttConnectionRow, MqttFilterRow, MqttPacketRow, MqttRow, MqttSubscriptionRow, MqttTopicFlowRow,
};

pub(super) fn mqtt_row(r: MqttRecord) -> MqttRow {
    match r {
        MqttRecord::Connection(c) => MqttRow::Connection(Box::new(connection_row(*c))),
        MqttRecord::Packet(p) => MqttRow::Packet(Box::new(packet_row(*p))),
        MqttRecord::Topic(t) => MqttRow::TopicFlow(topic_row(t)),
        MqttRecord::Subscription(s) => MqttRow::Subscription(subscription_row(s)),
        MqttRecord::Unfollowed(n) => MqttRow::Unfollowed(n),
    }
}

fn connection_row(c: MqttConnection) -> MqttConnectionRow {
    MqttConnectionRow {
        // Flow ids are non-negative by construction (`FlowId::from_first_frame`).
        flow_id: c.flow_id.0,
        first_ts: c.first_ts,
        last_ts: c.last_ts,
        client_ip: c.client.ip,
        client_port: c.client.port,
        server_ip: c.server.ip,
        server_port: c.server.port,
        transport: c.transport.as_str(),
        ws_path: c.ws_path,
        ws_host: c.ws_host,
        ws_subprotocol: c.ws_subprotocol,
        ws_close_code: c.ws_close_code,
        ws_compressed: c.ws_compressed,
        version: c.version.map(Version::level),
        bridge: c.bridge,
        partial: c.partial,
        protocol_name: c.protocol_name,
        client_id: c.client_id,
        assigned_client_id: c.assigned_client_id,
        clean_start: c.clean_start,
        keep_alive: c.keep_alive,
        server_keep_alive: c.server_keep_alive,
        session_expiry: c.session_expiry,
        username: c.username,
        password: c.password,
        password_len: c.password_len,
        auth_method: c.auth_method,
        auth: c.auth.map(AuthKind::as_str),
        will_topic: c.will_topic,
        will_qos: c.will_qos,
        will_retain: c.will_retain,
        will_payload_len: c.will_payload_len,
        will_payload: c.will_payload,
        connect_props: c.connect_props,
        connack_ts: c.connack_ts,
        connack_code: c.connack_code,
        session_present: c.session_present,
        connack_props: c.connack_props,
        login: c.login.map(Login::as_str),
        end_kind: c.end_kind.as_str(),
        disconnect_ts: c.disconnect_ts,
        disconnect_by: c.disconnect_by.map(Dir::as_str),
        disconnect_reason: c.disconnect_reason,
        broker_software: c.broker_software,
        packets_c2s: c.packets_c2s,
        packets_s2c: c.packets_s2c,
        publish_c2s: c.publish_c2s,
        publish_s2c: c.publish_s2c,
        payload_bytes_c2s: c.payload_bytes_c2s,
        payload_bytes_s2c: c.payload_bytes_s2c,
        subscribe_count: c.subscribe_count,
        pings: c.pings,
        last_ping_ts: c.last_ping_ts,
        bytes_c2s: c.bytes_c2s,
        bytes_s2c: c.bytes_s2c,
        stored_packets: c.stored_packets,
        packets_truncated: c.packets_truncated,
        malformed: c.malformed,
        protocol_errors: c.protocol_errors,
        gaps: c.gaps,
        state_dropped: c.state_dropped,
    }
}

fn packet_row(p: MqttPacket) -> MqttPacketRow {
    MqttPacketRow {
        flow_id: p.flow_id.0,
        seq: p.seq,
        ts: p.ts,
        dir: p.dir.as_str(),
        ptype: p.ptype.code(),
        flags: p.flags,
        packet_id: p.packet_id,
        qos: p.qos,
        retain: p.retain,
        dup: p.dup,
        topic: p.topic,
        topic_alias: p.topic_alias,
        topic_source: p.topic_source.map(TopicSource::as_str),
        size: p.size,
        payload_len: p.payload_len,
        payload: p.payload,
        payload_format: p.payload_format,
        content_type: p.content_type,
        reason_code: p.reason_code,
        reason_string: p.reason_string,
        ack_state: p.ack_state.map(AckState::as_str),
        ack_reason: p.ack_reason,
        ack_ns: p.ack_ns,
        filters: p
            .filters
            .into_iter()
            .map(|f| MqttFilterRow {
                filter: f.filter,
                options: f.options,
                granted: f.granted,
            })
            .collect(),
        props: p.props,
        malformed: p.malformed,
    }
}

fn topic_row(t: MqttTopicStat) -> MqttTopicFlowRow {
    MqttTopicFlowRow {
        flow_id: t.flow_id.0,
        dir: t.dir.as_str(),
        // The empty topic is the bucket of the other topics (an MQTT topic is never empty).
        topic: t.topic.unwrap_or_default(),
        messages: t.messages,
        payload_bytes: t.payload_bytes,
        first_ts: t.first_ts,
        last_ts: t.last_ts,
        qos: t.qos,
        retained: t.retained,
        max_payload: t.max_payload,
    }
}

fn subscription_row(s: MqttSubscription) -> MqttSubscriptionRow {
    MqttSubscriptionRow {
        flow_id: s.flow_id.0,
        seq: s.seq,
        idx: s.idx,
        ts: s.ts,
        filter: s.filter,
        qos: s.qos,
        options: s.options,
        granted: s.granted,
        shared_group: s.shared_group,
        wildcard: s.wildcard,
        unsubscribed_ts: s.unsubscribed_ts,
    }
}
