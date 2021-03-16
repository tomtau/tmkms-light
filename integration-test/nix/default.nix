{ sources ? import ./sources.nix }:
import sources.nixpkgs {
  overlays = [ ];
  config = { };
}