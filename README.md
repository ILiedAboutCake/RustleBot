# RustleBot
Destiny.GG chat bot to go along OverRustle.com. Another dumb project by ILiedAboutCake.

Run with RustleBot.py -r prod 

## Commands
Commands                                     | Result
---------------------------------------------|---
!rbstat                                     | Outputs Bot uptime / admins / and Ratelimit
!yee                                        | Outputs the YEE emote, verifies core parts of script are working / not banned 
!eval [command]                             | Allows raw exec of python shellcode. This is restricted to the bot owner. 
!apicheck                                   | Outputs the status of the API endpoint status / load / connections
!corecheck                                  | Outputs the status of the Frontend endpoint status / load / connections
!reload [stream]                            | Sends a page refresh to anything called [stream]
!punt [from] [to]                           | Sends users [from] to a new stream [to]
!rustlebot                                  | 7 sub commands, read below 

!RustleBot                                    | Result
---------------------------------------------|---
admin add [username]                                    | Adds username to allowed command users
admin delete [username]                                 | Removes username from allowed command users
admin check [username]                                  | Check if the user is already an admin. We all forget things
ratelimit [seconds]                                     | How often the bot is allowed to talk in chat (in seconds)
save                                                    | Saves pickle files to disk
uptime                                                  | How long since the bot has been enabled
emotes                                                  | Query destiny.gg for the latest emotes

### !punt examples

Punt any stream or channel with "iliedaboutcake" to overrustle.com/twitch/destiny (stream punt)
>!punt iliedaboutcake twitch/destiny

This also works for punting to other services (Any service supported on OverRustle.com)
>!punt iliedaboutcake hitbox/xj9lol

Punt any stream or channel with "iliedaboutcake" to overrustle.com/destiny (channel punt)
>!punt iliedaboutcake destiny
