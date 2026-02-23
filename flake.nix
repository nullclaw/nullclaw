{
  description = "nullclaw";
  inputs = {
    zig2nix.url = "github:Cloudef/zig2nix";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    { zig2nix, treefmt-nix, ... }:
    let
      flake-utils = zig2nix.inputs.flake-utils;
    in
    (flake-utils.lib.eachDefaultSystem (
      system:
      let
        env = zig2nix.outputs.zig-env.${system} {
          zig = zig2nix.outputs.packages.${system}.zig-latest;
        };
        pkgs = env.pkgs;
        project = "nullclaw";
        mkPackage =
          {
            optimize ? "ReleaseSmall",
          }:
          env.package {
            pname = project;
            src = ./.;

            zigBuildZonLock = ./build.zig.zon2json-lock;

            zigBuildFlags = [ "-Doptimize=${optimize}" ];

            nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.autoPatchelfHook ];

            meta = with pkgs.lib; {
              mainProgram = project;
              description = "Fastest, smallest, and fully autonomous AI assistant infrastructure written in Zig ";
              homepage = "https://github.com/nullclaw/nullclaw";
              license = licenses.mit;
              maintainers = [
                {
                  name = "Igor Somov";
                  github = "DonPrus";
                }
                {
                  name = "psynyde";
                  github = "psynyde";
                }
              ];
              platforms = platforms.all;
            };
          };
      in
      {
        packages.default = pkgs.lib.makeOverridable mkPackage { };
        devShells.default = env.mkShell {
          name = project;
          packages = with pkgs; [
            zls
          ];
          shellHook = ''
            echo -e '(¬_¬") Entered ${project} :D'
          '';
        };

        formatter = treefmt-nix.lib.mkWrapper pkgs {
          projectRootFile = "flake.nix";
          programs = {
            nixfmt.enable = true;
            zig.enable = true;
          };
        };
      }
    ));
}
