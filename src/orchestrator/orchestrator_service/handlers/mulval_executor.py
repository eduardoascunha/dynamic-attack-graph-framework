"""
MulVAL Executor: Handles MulVAL attack graph generation.
"""

import os
import subprocess
from pathlib import Path

from ..utils.logger import Logger


class NoAttackPathsFoundError(RuntimeError):
    """Raised when MulVAL completes without finding an attack path."""


class MulValExecutor:
    """
    Executes MulVAL graph generation commands.
    """

    _REQUIRED_OUTPUTS = (
        'AttackGraph.dot',
        'AttackGraph.xml',
        'VERTICES.CSV',
        'ARCS.CSV',
    )

    def __init__(self, mulval_root: str, timeout_seconds: int = 300):
        """
        Initialize MulVAL executor.
        
        Args:
            mulval_root: Path to MulVAL root directory.
            timeout_seconds: Timeout for graph generation in seconds.
        """
        self._log = Logger.get_logger()
        self.mulval_root = Path(mulval_root)
        self.timeout_seconds = timeout_seconds
        self.graph_gen_script = self.mulval_root / 'utils' / 'graph_gen.sh'
        
        self._log.debug(f"MulVAL root: {self.mulval_root}")
        self._log.debug(f"Graph generation script: {self.graph_gen_script}")

    def generate_graph(
        self, 
        scenario_file: str, 
        output_dir: str,
    ) -> bool:
        """
        Generate attack graph using MulVAL.
        
        Args:
            scenario_file: Path to the input scenario file.
            output_dir: Directory where graph outputs will be stored.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            if not self.graph_gen_script.exists():
                self._log.error(f"Graph generation script not found: {self.graph_gen_script}")
                return False
            
            scenario_path = Path(scenario_file)
            if not scenario_path.exists():
                self._log.error(f"Scenario file not found: {scenario_file}")
                return False
            
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            cmd = [str(self.graph_gen_script), str(scenario_path), '-v']
            
            self._log.info(f"Executing: {' '.join(cmd)}")
            self._log.info(f"Working directory: {output_path}")
            
            env = os.environ.copy()
            env['MULVALROOT'] = str(self.mulval_root)
            extra_paths = f"{self.mulval_root}/bin:{self.mulval_root}/utils"
            env['PATH'] = f"{extra_paths}:{env.get('PATH', '')}"
            
            # Execute MulVAL
            result = subprocess.run(
                cmd,
                cwd=str(output_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds
            )
            
            if result.stdout:
                self._log.debug(f"MulVAL stdout: {result.stdout}")
            no_attack_paths_found = self._is_no_attack_paths_result(result)

            if result.stderr and not no_attack_paths_found:
                self._log.warning(f"MulVAL stderr: {result.stderr}")

            if no_attack_paths_found:
                raise NoAttackPathsFoundError("No attack paths found")
            
            if result.returncode == 0:
                self._log.info("MulVAL graph generation completed successfully")

                missing_outputs = []
                for output_file in self._REQUIRED_OUTPUTS:
                    output_file_path = output_path / output_file
                    if output_file_path.exists():
                        self._log.info(f"Generated: {output_file_path}")
                    else:
                        missing_outputs.append(output_file)

                if missing_outputs:
                    self._log.error(
                        "MulVAL completed but required outputs are missing: %s",
                        ', '.join(missing_outputs),
                    )
                    return False

                return True
            
            self._log.error(f"MulVAL execution failed with return code {result.returncode}")
            return False
                
        except subprocess.TimeoutExpired:
            self._log.error(f"MulVAL execution timed out after {self.timeout_seconds} seconds")
            return False
        except NoAttackPathsFoundError:
            raise
        except Exception as e:
            self._log.error(f"Error executing MulVAL: {e}", exc_info=True)
            return False

    def _is_no_attack_paths_result(self, result: subprocess.CompletedProcess[str]) -> bool:
        """Return True when MulVAL reports that no attack paths exist."""
        no_attack_paths_marker = "No attack paths found."
        return no_attack_paths_marker in result.stderr