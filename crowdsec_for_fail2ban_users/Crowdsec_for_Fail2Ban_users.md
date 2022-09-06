# Crowdsec for Fail2Ban users

It's not a secret that Fail2Ban is a nice way to keep some noise away from your systems and especially log files by parsing the latter one and getting rid of hosts hammering your systems. As seen on my previous post, it's quite a ton of cpu power wasted - which boils down to energy usage in the end.

So first off, CrowdSec is not just 'one tool' to do the job as it uses multiple components that we need to talk about.

## The Central API

The central API or CAPI is the brains of the whole operation. That's where you send in your reports if you choose to and/or get your ban lists from.



## The Local API

The local API or LAPI is like our big CAPI, just on your own end, communicating with all the parts - even across the network.



## The Parser(s)

Parsers are what read your logs. The data presented to them is getting parsed and alerts are being generated - those are sent to your LAPI and CAPI (if you wish to), after being 'enriched' to make sense to the system.



## The Bouncer(s)

A bouncer is exactly what the label says - this is what does the actual blocking by advising your firewall (iptables, nftables, pf, windows firewall or even just IP lists) to take action.



## Why CowdSec?

Well, so why crowdsec, you may ask. And that's a good question. Fail2ban was written back in 2004 roughly 17 years ago as of the writing of this post and was improved since. But due to its old age and the fact that attacks also evolve, we had to take a new approach to detect stuff that fail2ban would miss - Events which even your LAPI could miss.

## What do I send, what do I get?

That's an easy thing: If you share your SSH attackers, you will get the SSH offender list back - in other words, you get what you share. In case you would like the whole list shared, consider either sharing more or get a subscription.

## How efficient is it?

In my books, I was already using fail2ban for quite a while and it did 'something'. I watched the firewall blocking a couple of hosts but didn't really consider it a game changer as someone had to attack us first to show up in the logs. CrowdSec on the other hand gave me around 92% more hosts on my lists due to them already having annoyed other hosts and thus are being blocked way before they start hammering my machines.

## Why not just use different ports?

Different ports may not work for every scenario out there. Imagine you'd be running your webserver on a different set of ports than 80/443. How would you make that publicly available? 

Standards are there for a reason - and a reason why people attack those.

## Blocking vs Captcha

Some people may be afraid of blocking valid traffic due to changing IP addresses. I get that fear - that's why we offer bouncers like the Wordpress bouncer which lets you use captchas instead of just blocking hosts if you feel like.

I did a lot of research back in my Wordpress days where I was blocking spam comments with a central list as I did run multiple of those. My observations were that most users of my plugins were curiously on my blocklist as well. In other words, it was mostly servers being blocked as they have been taken over due to bad security on their end and in more than 7 years time with my plugin, only 5 IPs were going for my delisting request page - all of those removals were requested from a different IP, not the one actually being listed which lets me assume that  those requests came from the spammers themselves. In other words, I do not see harm in just blocking annoying IP addresses.


