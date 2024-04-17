package play_off

import rego.v1

default hello := false

hello if input.message == "world"

pi if input.value == 3.14

rect := {"width": 2, "height": 4}

check_rect if rect == {"height": 4, "width": 2}

width_check if rect.height > 3

t2 if {
	x := 4
	y := 3
	x > y
}

public_network contains net.id if {
	some net in input.networks # some network exists and..
	net.public # it is public.
}

shell_accessible contains server.id if {
	some server in input.servers
	"telnet" in server.protocols
}

no_telnet_exposed if {
	every server in input.servers {
		every protocol in server.protocols {
			not "telnet" == protocol
		}
	}
}

any_public_networks if {
	some net in input.networks # some network exists and..
	net.public # it is public.
}

hostnames contains name if {
	name := input.sites[_].servers[_].hostname
}

instances contains instance if {
	server := input.sites[_].servers[_]
	instance := {"address": server.hostname, "name": server.name}
}

# Define user "bob" for test input.
user := "bob"

# Define two sets of users: power users and restricted users. Accidentally
# include "bob" in both.
power_users := {"alice", "bob", "fred"}

restricted_users := {"bob", "kim"}

# Power users get 32GB memory.
max_memory := 32 if power_users[user]

users_by_role[role][id] := user if {
	some user in input.users
	id := user.id
	role := user.role
}
