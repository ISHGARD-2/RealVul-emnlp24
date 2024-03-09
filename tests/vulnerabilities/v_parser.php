<?php
class a{
    function a(){
        while(1==1){
            if(1==1){
                function b(){
                    $taint = $_GET['test'];
                     //print($taint);
                    echo system(trim('ls'.$taint));
                }
             }
        }
    }
}
?>