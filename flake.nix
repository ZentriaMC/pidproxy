{
  description = "pidproxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      supportedSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    flake-utils.lib.eachSystem supportedSystems
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        rec {
          packages.pidproxy = pkgs.callPackage ./. { };
          packages.pidproxy-static = packages.pidproxy.override { enableStatic = true; };
          defaultPackage = packages.pidproxy;
        })
    // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      rec {
        devShells.default = pkgs.mkShell {
          packages = [
            # NOTE: addlicense -f etc/HEADER -c "Zentria OÜ" -y "2020-$(date +%Y)" *.c *.h
            pkgs.addlicense
          ];
        };
      });
}
