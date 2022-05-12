import type { Handler, HandlerInboundMessage } from '@aries-framework/core/build/agent/Handler'

/**
 * Handler for incoming push notification device info messages
 */
export class PushNotificationsFcmAndroidGetDeviceInfoHandler implements Handler {
  public supportedMessages = [PushNotificationsFcmAndroidGetDeviceInfoMessage]

  /**
  /* We don't really need to do anything with this at the moment
  /* The result can be hooked into through the generic message processed event
   */
  public async handle(inboundMessage: HandlerInboundMessage<PushNotificationsFcmAndroidGetDeviceInfoHandler>) {
    inboundMessage.assertReadyConnection()
  }
}
