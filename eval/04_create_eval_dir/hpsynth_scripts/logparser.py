from collections import deque


def unassert(constraint):
    constraint = constraint.strip()
    assert constraint.startswith('(assert ')
    assert constraint.endswith(')')
    return constraint[7:-1].strip()


class LogParser:
    OUTPUT_PREAMBLE = 'Message bytes:'
    PATH_PREAMBLE = 'Path Assertions:'

    def __init__(self, lines):
        self.lines = deque(lines)

    def parse(self):
        while self.lines:
            self._skip_path_preamble()
            path_constraints = self._parse_path_constraints()
            self._skip_output_preamble()
            output_expr = self._parse_output_expr()
            yield path_constraints, output_expr

    def _parse_path_constraints(self):
        constraints = []
        current_constraint = None
        level = 0
        while self.lines:
            line = self.lines[0]
            if line.startswith(self.OUTPUT_PREAMBLE):
                break

            self.lines.popleft()
            if line.startswith('(assert'):
                if current_constraint:
                    constraints.append(current_constraint)
                current_constraint = line
                level = line.count('(') - line.count(')')
            elif len(line) > 1 and level != 0:
                if current_constraint:
                    current_constraint += line
                    level += line.count('(') - line.count(')')
            else:
                if current_constraint:
                    constraints.append(current_constraint)
                    current_constraint = None

        return [unassert(c) for c in constraints]

    def _parse_output_expr(self):
        output_expressions = []
        current_expression = None
        while self.lines:
            line = self.lines[0]
            if line.startswith(self.PATH_PREAMBLE):
                break

            self.lines.popleft()
            if line.startswith('SYM: ') or line.startswith('CON: '):
                if current_expression:
                    output_expressions.append(current_expression)
                current_expression = line[4:]
            elif len(line) > 1 and str.isspace(line[0]):
                if current_expression:
                    current_expression += line
            else:
                if current_expression:
                    output_expressions.append(current_expression)
                    current_expression = None

        return output_expressions

    def _skip_path_preamble(self):
        while self.lines:
            line = self.lines[0]
            self.lines.popleft()
            if line.startswith(self.PATH_PREAMBLE):
                break

    def _skip_output_preamble(self):
        while self.lines:
            line = self.lines[0]
            self.lines.popleft()
            if line.startswith(self.OUTPUT_PREAMBLE):
                break


if __name__ == '__main__':
    with open('./examples/sym__usr_sbin_in.ntalkd_518') as f:
        lines = f.read().splitlines()

    p = LogParser(lines)
    for i, (constraints, output) in enumerate(p.parse()):
        print(f'Testcase {i}:')
        print(constraints)
        print(' --> ')
        print(output)
        print()
