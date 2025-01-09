# network-observer

Docker container for monitoring local network(s) for unexpected device
connections or disconnections.

## Building

```shell
$ sudo docker build --tag "chief8192/network-observer" .
```

## Configuring

Configuration is done by way of a `config.json` file with the following format:

```json
{
  "subnets": [""],

  "pushover_app_token": "",
  "pushover_user_key": "",

  "permanent_devices": [{ "mac": "", "name": "" }],
  "transient_devices": [{ "mac": "", "name": "" }],
  "interloper_devices": [{ "mac": "", "name": "" }]
}
```

### Configuration properties

| Property             | Required | Description                                                                                                |
| -------------------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `subnets`            | Yes      | The subnet(s) to periodically scan. Must be strings in slash notation.                                     |
| `pushover_app_token` | No       | [Pushover](https://pushover.net/) app token to use when sending push notifications.                        |
| `pushover_user_key`  | No       | [Pushover](https://pushover.net/) user key to use when sending push notifications.                         |
| `permanent_devices`  | No       | List of MAC+name dicts. Any device not detected will result in a notification.                             |
| `transient_devices`  | No       | List of MAC+name dicts. Known devices with regular, intermittent connectivity (e.g. wireless devices).     |
| `interloper_devices` | No       | List of MAC+name dicts. Known devices with irregular connectivity. Generates a notification when detected. |

## Running

```shell
$ sudo docker run \
    --cap-add="NET_ADMIN" \
    --cap-add="NET_RAW" \
    --detach \
    --name="network-observer" \
    --network="host" \
    --restart="always" \
    --volume="${PWD}/config.json:/config.json" \
    "chief8192/network-observer:latest"
```

## Notifications

If configured to do so, `network-observer` will generate Pushover notifications
in multiple situations:

- When a device specified in `permanent_devices` **is not** detected by ARP scan for 10 minutes.
- When a device specified in `permanent_devices` is detected by ARP scan after 10 minutes of absence.
- When a device specified in `interloper_devices` **is** detected by ARP scan. This notification has a 6 hour cooldown.
- When an altogether unknown devices is detected by ARP scan. This notification has a 30 minute cooldown.
- Additionally, the detection of an unknown device triggers an NMAP scan of that device. The results of this scan are sent via notification.
