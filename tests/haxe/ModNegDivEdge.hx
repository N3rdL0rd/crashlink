class ModNegDivEdge {
    static function main() {
        Sys.println(-7 % 3);
        Sys.println(7 % -3);
        Sys.println(-7 % -3);
        Sys.println(-7 / 3);
        var minInt = -2147483648;
        Sys.println(minInt - 1);
        Sys.println(minInt * -1);
        var a = 2147483647;
        Sys.println(a + 1);
        Sys.println(minInt % -1);
    }
}
