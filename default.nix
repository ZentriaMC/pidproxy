{ pkgs ? import <nixpkgs> { }
, lib ? pkgs.lib
, enableStatic ? false
, ...
}:

pkgs.stdenv.mkDerivation {
  pname = "pidproxy";
  version = "0.0.1";
  src = ./.;

  buildInputs = with pkgs; lib.optional enableStatic upx;
  nativeBuildInputs = with pkgs; [ (if enableStatic then musl else glibc) ];

  patchPhase = lib.optionalString (!enableStatic) ''
    sed -i 's/-static //g' Makefile
  '';

  preBuild = with pkgs; lib.optionalString enableStatic ''
    makeFlagsArray+=("CC=${stdenv.cc.targetPrefix}cc -isystem ${musl.dev}/include -B${musl}/lib -L${musl}/lib")
  '';

  postBuild = lib.optionalString enableStatic ''
    make pidproxy.upx
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp ./pidproxy${lib.optionalString enableStatic ".upx"} $out/bin/pidproxy
  '';

  doCheck = false; # no tests
}
