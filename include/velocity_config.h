#ifndef BAREIRON_VELOCITY_CONFIG_H
#define BAREIRON_VELOCITY_CONFIG_H

/* Uncomment to require modern Velocity forwarding on the backend. */
#define ENABLE_VELOCITY_FORWARDING

/* Must match forwarding.secret in velocity.toml. */
#define VELOCITY_FORWARDING_SECRET "change-this-secret"

#endif
