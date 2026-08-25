class PreIncCond {
    static function main() {
        var i = 0;
        while (++i < 4) {
            Sys.println(i);
        }
        var j = 0;
        do {
            Sys.println(--j);
        } while (j > -3);
    }
}
