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
    flake-utils.lib.eachSystem supportedSystems (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      rec {
        packages.pidproxy = pkgs.callPackage ./. { };
        packages.pidproxy-static = pkgs.callPackage ./. { enableStatic = true; };
        defaultPackage = packages.pidproxy;

        hydraJobs = {
          build = packages.pidproxy;
          build-static = packages.pidproxy-static;
        };
      });
}
