// Calls inside `&&`/`||` groups: each call has to run exactly when the source
// reaches it, and in its original order relative to the field reads around it.
class ShortCircuitCallOrder {
    static var log:String = "";
    static var counter:Int = 0;

    static function f(tag:String, v:Int):Int {
        log += tag;
        counter++;
        return v;
    }

    static function groups(a:Int, b:Int, c:Int, d:Int):String {
        if ((f("a", a) == 1 && f("b", b) > 0) || (f("c", c) != 2 && f("d", d) < 3)) {
            return "T";
        }
        return "F";
    }

    static function readThenCall(x:Int):String {
        // `counter` is read before f() bumps it.
        if (x > 0 && counter + f("e", x) == 3) {
            return "Y";
        }
        return "N";
    }

    static function callThenRead(x:Int):String {
        // f() bumps `counter` before it is read.
        if (x > 0 && f("g", x) + counter == 3) {
            return "Y";
        }
        return "N";
    }

    static function pick(s:String):String {
        if (s.indexOf("L") != -1 && s.indexOf("R") != -1) {
            return "LR";
        } else if (s.indexOf("L") != -1 && s.indexOf("T") != -1) {
            return "LT";
        } else if (s.indexOf("R") != -1 || s.indexOf("T") != -1) {
            return "R|T";
        }
        return "-";
    }

    static function main() {
        var out = "";
        for (a in 0...3) {
            for (b in -1...2) {
                for (c in 1...4) {
                    for (d in 1...5) {
                        log = "";
                        out += groups(a, b, c, d) + log + ",";
                    }
                }
            }
        }
        Sys.println(out);

        for (x in -1...3) {
            for (start in 0...3) {
                counter = start;
                log = "";
                var r1 = readThenCall(x);
                counter = start;
                var r2 = callThenRead(x);
                Sys.println(x + " " + start + " " + r1 + r2 + " " + log);
            }
        }

        for (s in ["LR", "LT", "R", "T", "", "LTR", "X"]) {
            Sys.println(s + " " + pick(s));
        }
    }
}
