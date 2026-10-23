import unittest

from datapce_scan import shellparse as sp


def argvs(text):
    return [c.argv for c in sp.parse(text)]


class SplitTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(argvs("git status"), [["git", "status"]])

    def test_operators(self):
        self.assertEqual(argvs("cd a && rm -rf b || echo x; ls | wc -l & sleep 1"),
                         [["cd", "a"], ["rm", "-rf", "b"], ["echo", "x"], ["ls"], ["wc", "-l"],
                          ["sleep", "1"]])

    def test_newline_is_separator(self):
        self.assertEqual(argvs("cd /tmp\nrm -rf /"), [["cd", "/tmp"], ["rm", "-rf", "/"]])

    def test_line_continuation_joins(self):
        self.assertEqual(argvs("rm -rf \\\n  build"), [["rm", "-rf", "build"]])

    def test_quotes_removed_and_kept_together(self):
        self.assertEqual(argvs("git commit -m 'a && b; c'"), [["git", "commit", "-m", "a && b; c"]])

    def test_quoted_newline_is_not_separator(self):
        self.assertEqual(argvs('echo "a\nb"'), [["echo", "a\nb"]])

    def test_comment_dropped(self):
        self.assertEqual(argvs("ls # rm -rf /\npwd"), [["ls"], ["pwd"]])

    def test_hash_inside_word_is_not_comment(self):
        self.assertEqual(argvs("echo a#b"), [["echo", "a#b"]])

    def test_redirections_dropped(self):
        self.assertEqual(argvs("ls -la > out.txt 2>&1"), [["ls", "-la"]])
        self.assertEqual(argvs("cat < in.txt >> log"), [["cat"]])

    def test_env_assignments_split_off(self):
        cmds = sp.parse("FOO=1 BAR='x y' make test")
        self.assertEqual(cmds[0].argv, ["make", "test"])
        self.assertEqual(cmds[0].assigns, {"FOO": "1", "BAR": "x y"})

    def test_heredoc_body_is_not_parsed(self):
        text = "cat > f.txt <<'EOF'\nrm -rf /\ngit push --force\nEOF\necho done"
        self.assertEqual(argvs(text), [["cat"], ["echo", "done"]])

    def test_heredoc_dash_and_unquoted(self):
        text = "cat <<-END\n\trm -rf /\n\tEND\nls"
        self.assertEqual(argvs(text), [["cat"], ["ls"]])

    def test_here_string_is_data(self):
        self.assertEqual(argvs("grep x <<< 'rm -rf /'"), [["grep", "x"]])

    def test_keywords_stripped(self):
        self.assertEqual(argvs("if true; then rm -rf x; fi"), [["true"], ["rm", "-rf", "x"]])
        self.assertEqual(argvs("for f in a b; do rm $f; done"), [["rm", "$f"]])

    def test_subshell_and_group(self):
        self.assertEqual(argvs("(cd a && ls) ; { pwd; }"), [["cd", "a"], ["ls"], ["pwd"]])

    def test_unbalanced_quote_falls_back(self):
        cmds = sp.parse("echo 'oops")
        self.assertTrue(cmds)
        self.assertTrue(all(c.fallback for c in cmds))


class NestedTests(unittest.TestCase):
    def test_bash_c(self):
        self.assertIn(["rm", "-fr", "/"], argvs("bash -c 'rm -fr /'"))

    def test_sh_lc_and_path(self):
        self.assertIn(["git", "push", "-f"], argvs('/bin/sh -lc "git push -f"'))

    def test_eval(self):
        self.assertIn(["rm", "-rf", "/"], argvs('eval "rm -rf /"'))

    def test_dollar_paren(self):
        self.assertIn(["rm", "-rf", "/"], argvs('echo "$(rm -rf /)"'))
        self.assertIn(["date"], argvs("x=$(date) && echo $x"))

    def test_backticks(self):
        self.assertIn(["whoami"], argvs("echo `whoami`"))

    def test_single_quoted_substitution_is_text(self):
        self.assertNotIn(["rm", "-rf", "/"], argvs("echo '$(rm -rf /)'"))

    def test_nested_depth_marked(self):
        cmds = sp.parse("bash -c 'ls'")
        self.assertEqual([c.depth for c in cmds], [0, 1])

    def test_wrappers_unwrapped(self):
        self.assertEqual(argvs("sudo -u root rm -rf /x")[-1], ["rm", "-rf", "/x"])
        self.assertEqual(argvs("env -i A=1 nohup timeout 5 git push --force")[-1],
                         ["git", "push", "--force"])
        self.assertEqual(argvs("xargs -n 1 rm -rf")[-1], ["rm", "-rf"])

    def test_find_exec(self):
        self.assertIn(["rm", "-rf", "{}"], argvs("find . -name x -exec rm -rf {} \\;"))

    def test_depth_limit(self):
        text = "bash -c " + "'bash -c \"bash -c ls\"'"
        cmds = sp.parse(text, max_depth=1)
        self.assertNotIn(["ls"], [c.argv for c in cmds])


class FamilyTests(unittest.TestCase):
    def test_family_basename(self):
        self.assertEqual(sp.family(["/usr/bin/git", "status"]), "git")
        self.assertEqual(sp.family([".venv/bin/python", "-m", "x"]), "python")

    def test_family_special(self):
        self.assertEqual(sp.family(["$EDITOR", "f"]), "(variable)")
        self.assertEqual(sp.family([]), "(none)")


class TempVarTests(unittest.TestCase):
    def test_mktemp_assignment_tracked(self):
        self.assertEqual(sp.temp_vars("d=$(mktemp -d) && rm -rf \"$d\""), {"d"})
        self.assertEqual(sp.temp_vars("d=$(date)"), set())
        self.assertEqual(sp.temp_vars("C=$(mktemp -d /tmp/x.XXXX)/r"), {"C"})

    def test_literal_vars_tracked(self):
        p = sp.parse("S=/tmp/x; export T=build; rm -rf $S")
        self.assertEqual(p.vars, {"S": "/tmp/x", "T": "build"})
        p = sp.parse("S=/tmp/x; S=$(date)")
        self.assertIsNone(p.vars["S"])


class HeredocFreeTests(unittest.TestCase):
    def test_bodies_removed_rest_kept(self):
        t = "cat > f <<'EOF'\nosascript x\nEOF\necho ok | osascript"
        out = sp.heredoc_free(t)
        self.assertNotIn("osascript x", out)
        self.assertIn("echo ok | osascript", out)
        self.assertEqual(sp.heredoc_free("a <<< b"), "a <<< b")


if __name__ == "__main__":
    unittest.main()
