{
  description = "Ghidra built from this source tree, plus an agentic GUI test harness";

  # Pinned to the nixpkgs revision whose `ghidra` is exactly 12.1.2, matching
  # this checkout (see default.nix / shell.nix for the same pin).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/534ee3d8beb1737b5342995f8837e2b2705ce0d8";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAll = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      # NOTE: flake commands only see git-tracked files. `git add` the nix files
      # (and anything else you want in `src`) before `nix build`, or use the
      # non-flake `nix-build` which has no such requirement.
      packages = forAll (
        system:
        let
          ghidra = (import ./default.nix { pkgs = pkgsFor system; }).ghidra-local;
        in
        {
          inherit ghidra;
          default = ghidra;
        }
      );

      devShells = forAll (system: {
        default = import ./shell.nix { pkgs = pkgsFor system; };
      });

      apps = forAll (system: {
        default = {
          type = "app";
          program = "${(import ./default.nix { pkgs = pkgsFor system; }).ghidra-local}/bin/ghidra";
        };
      });
    };
}
