class SwitchMulti2 {
    static function main() {
        var x = 2;
        Sys.println(switch (x) { case 1, 2: "low"; default: "other"; });
    }
}
