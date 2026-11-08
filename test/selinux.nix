{
  pkgs,
  source,
}:

let
  inherit (pkgs) lib;

  systemdWithSelinux = pkgs.systemd.override { withSelinux = true; };

  selinuxConfig = pkgs.writeText "palisade-selinux-config" ''
    SELINUX=enforcing
    SELINUXTYPE=refpolicy
  '';

  semanageConfig = pkgs.writeText "palisade-semanage.conf" ''
    compiler-directory = ${pkgs.policycoreutils}/libexec/selinux/hll
    usepasswd = false
    disable-genhomedircon = true

    [setfiles]
    path = ${pkgs.policycoreutils}/bin/setfiles
    args = -q -c $@ $<
    [end]

    [sefcontext_compile]
    path = ${lib.getBin pkgs.libselinux}/bin/sefcontext_compile
    args = $@
    [end]
  '';

  # Palisade executes after applying no_new_privs and mounting a nosuid root.
  # SELinux requires these explicit process2 permissions when exec changes the
  # domain; production policy for a Palisade domain needs the same allowances.
  palisadeTestPolicy = pkgs.writeText "palisade-test.cil" ''
    (allow kernel_t init_t (process2 (nnp_transition nosuid_transition)))
    (allow init_t tmp_t (file (entrypoint)))
  '';

  # nixpkgs ships refpolicy as policy packages. Assemble those packages into
  # the binary policy and contexts that systemd expects in the initrd.
  policy =
    pkgs.runCommand "palisade-selinux-policy" { nativeBuildInputs = [ pkgs.policycoreutils ]; }
      ''
        mkdir -p "$out/etc/selinux/refpolicy" "$out/var/lib/selinux/refpolicy"
        cp -r ${pkgs.selinux-refpolicy}/etc/selinux/refpolicy/. "$out/etc/selinux/refpolicy/"
        chmod -R u+w "$out/etc/selinux/refpolicy"
        install -m 0644 ${selinuxConfig} "$out/etc/selinux/config"

        args=()
        for module in ${pkgs.selinux-refpolicy}/share/selinux/refpolicy/*.pp; do
          args+=( -i "$module" )
        done
        # semodule derives the module name from the filename; a Nix store hash
        # is not a valid SELinux identifier.
        cp ${palisadeTestPolicy} palisade_test.cil
        args+=( -i "$PWD/palisade_test.cil" )

        if ! semodule \
          --noreload \
          --path "$out" \
          --store refpolicy \
          --config ${semanageConfig} \
          "''${args[@]}" \
          >semodule.log 2>&1
        then
          cat semodule.log >&2
          exit 1
        fi

        test -n "$(find "$out/etc/selinux/refpolicy/policy" -name 'policy.*' -type f -print -quit)"
        test -s "$out/etc/selinux/refpolicy/contexts/files/file_contexts.bin"
      '';

in

pkgs.testers.runNixOSTest {
  name = "palisade-selinux";

  # GitHub's hosted aarch64 runner does not expose /dev/kvm. The test remains
  # architecture-native and QEMU falls back to TCG when acceleration is absent.
  requiredFeatures.kvm = false;

  nodes.machine =
    { lib, pkgs, ... }:
    {
      boot.kernelPatches = [
        {
          name = "selinux";
          patch = null;
          structuredExtraConfig = with lib.kernel; {
            SECURITY_SELINUX = yes;
            SECURITY_SELINUX_BOOTPARAM = yes;
            SECURITY_SELINUX_DEVELOP = yes;
            SECURITY_SELINUX_AVC_STATS = yes;
          };
        }
      ];
      boot.kernelParams = [
        "selinux=1"
        # The NixOS test root is assembled from unlabeled store paths. Load the
        # policy in the initrd, then enable enforcement once stage 2 is up.
        "enforcing=0"
      ];
      security.lsm = lib.mkBefore [ "selinux" ];

      # PID 1 loads SELinux policy before starting any initrd units.
      systemd.package = systemdWithSelinux;
      boot.initrd.systemd.package = systemdWithSelinux;
      boot.initrd.systemd.contents."/etc/selinux".source = "${policy}/etc/selinux";
      environment.etc."selinux".source = "${policy}/etc/selinux";

      environment.systemPackages = [
        (lib.getBin pkgs.libselinux)
        pkgs.policycoreutils
        pkgs.zig_0_17
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("setenforce 1")

    with subtest("SELinux and Landlock are active"):
        machine.succeed("grep -qw selinux /sys/kernel/security/lsm")
        machine.succeed("grep -qw landlock /sys/kernel/security/lsm")
        machine.succeed("sestatus | grep -F 'SELinux status:                 enabled'")
        machine.succeed("sestatus | grep -F 'Current mode:                   enforcing'")
        machine.succeed("sestatus | grep -F 'Loaded policy name:             refpolicy'")

    with subtest("SELinux enforces a denial"):
        machine.fail("modprobe ext2")
        machine.succeed("journalctl -k --grep='avc: *denied.*module_load'")

    with subtest("Palisade SELinux unit tests"):
        machine.succeed("cp -r ${source} /tmp/palisade")
        machine.succeed("cd /tmp/palisade && zig build test-selinux")
  '';
}
