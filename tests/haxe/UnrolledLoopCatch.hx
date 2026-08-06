class UnrolledLoopCatch {
    static function main() {
        for (i in 0...3) {
            try {
                if (i == 1) {
                    throw "skip";
                }
                Sys.println(i);
            } catch (e:String) {
                Sys.println(e + i);
            }
            Sys.println("tail " + i);
        }
    }
}
