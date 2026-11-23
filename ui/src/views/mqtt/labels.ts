// Labels of MQTT codes and properties (names of the specifications, through the dictionaries).

import type { TFunction } from 'i18next';
import type { MqttVersion } from '../../api/types/MqttVersion';

/** `0x86`: a code as written in the specifications. */
export function hexCode(code: number): string {
  return `0x${code.toString(16).padStart(2, '0')}`;
}

const V3_CODES = [0, 1, 2, 3, 4, 5] as const;
type V3Code = (typeof V3_CODES)[number];
const REASON_CODES = [
  0, 1, 2, 4, 16, 17, 24, 25, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146,
  147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
] as const;
type ReasonCode = (typeof REASON_CODES)[number];
const PROPS = [
  'payload_format', 'message_expiry', 'content_type', 'response_topic', 'correlation_data', 'subscription_id', 'session_expiry',
  'assigned_client_id', 'server_keep_alive', 'auth_method', 'auth_data_len', 'request_problem_info', 'will_delay',
  'request_response_info', 'response_info', 'server_reference', 'reason_string', 'receive_maximum', 'topic_alias_maximum',
  'topic_alias', 'maximum_qos', 'retain_available', 'maximum_packet_size', 'wildcard_available', 'sub_id_available',
  'shared_available', 'user_property', 'user_properties_dropped', 'properties_error',
] as const;
type PropName = (typeof PROPS)[number];

const isV3 = (c: number): c is V3Code => (V3_CODES as readonly number[]).includes(c);
const isReason = (c: number): c is ReasonCode => (REASON_CODES as readonly number[]).includes(c);
const isProp = (n: string): n is PropName => (PROPS as readonly string[]).includes(n);

/** Label of a CONNACK return code (3.x) or of a 5.0 reason code; its value when unknown. */
export function reasonLabel(t: TFunction, code: number, version: MqttVersion | null): string {
  if (version !== '5.0' && isV3(code)) return t(`views.mqtt.connack.v3.${code}`);
  return isReason(code) ? t(`views.mqtt.reason.${code}`) : hexCode(code);
}

/** Display name of a property (its stored name when unknown). */
export function propLabel(t: TFunction, name: string): string {
  return isProp(name) ? t(`views.mqtt.prop.${name}`) : name;
}
