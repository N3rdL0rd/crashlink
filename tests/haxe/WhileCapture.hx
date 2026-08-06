class WhileCapture {
    static function main() {
        var j = 0;
        var g:Void->Void = null;
        while (j < 1) {
            g = () -> Sys.println(j);
            j++;
        }
        g();
    }
}
