class ShortCircuitSideEffect {
    static var log:String = "";
    static function sideT():Bool { log += "T"; return true; }
    static function sideF():Bool { log += "F"; return false; }

    static function main() {
        log = "";
        if (sideF() && sideT()) {}
        Sys.println(log); // F only

        log = "";
        if (sideT() || sideF()) {}
        Sys.println(log); // T only

        log = "";
        if (sideT() && sideF()) {}
        Sys.println(log); // TF

        log = "";
        if (sideF() || sideT()) {}
        Sys.println(log); // FT

        log = "";
        var r = sideF() && sideT() || sideT();
        Sys.println(log + " " + r);
    }
}
