# blankres

An apport-style crash reporting system in Rust: a daemon that turns crashes into reports, a GTK
desktop window for reviewing and consenting to them, and a server that ingests what gets sent.

The design question this project exists to answer is not "how do we collect crash data" — apport
answers that well — but **what does collecting it cost the machine it runs on**. Apport's own wiki
concedes that it "takes a nontrivial amount of CPU and I/O resources" and delays restarting a
crashed program by seconds. Every significant decision here follows from refusing that cost.

How it works, how it avoids that cost, and how to run and test it are in [DESIGN.md](DESIGN.md).
