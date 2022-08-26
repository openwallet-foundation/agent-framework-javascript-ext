import { AgentMessage } from '@aries-framework/core'
import { Equals } from 'class-validator'

interface PushNotificationsGetDeviceInfoOptions {
  id?: string
}

/**
 * Message to get the device information from another agent for push notifications
 *
 * @todo ADD RFC
 */
export class PushNotificationsGetDeviceInfoMessage extends AgentMessage {
  @Equals(PushNotificationsGetDeviceInfoMessage.type)
  public readonly type = PushNotificationsGetDeviceInfoMessage.type
  public static readonly type = 'https://didcomm.org/push-notifications-native/1.0/get-device-info'

  public constructor(options: PushNotificationsGetDeviceInfoOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
    }
  }
}
