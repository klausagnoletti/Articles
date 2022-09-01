```blockdiag
nwdiag {
  network internet {
      agent-2 [address = "210.x.x.1"];
      agent-3 [address = "210.x.x.2"];
  }
  network internal {
      address = "10.0.0.0/24";

      agent-2 [address = "10.0.0.2"];
      agent-3 [address = "10.0.0.3"];

  }
}
```