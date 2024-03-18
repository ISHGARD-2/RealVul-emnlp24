<?php
/********************************************************************************\
 * Copyright (C) ViCarePlus, Visolve (vicareplus_engg@visolve.com)              *
 *                                                                              *
 * This program is free software; you can redistribute it and/or                *
 * modify it under the terms of the GNU General Public License                  *
 * as published by the Free Software Foundation; either version 2               *
 * of the License, or (at your option) any later version.                       *
 *                                                                              *
 * This program is distributed in the hope that it will be useful,              *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
 * GNU General Public License for more details.                                 *
 *                                                                              *
 * You should have received a copy of the GNU General Public License            *
 * along with this program; if not, write to the Free Software                  *
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  *
 \********************************************************************************/
require_once("../globals.php");
require_once("$srcdir/patient.inc");
require_once("../../custom/code_types.inc.php");

$info_msg = "";
$codetype = $_REQUEST['codetype'];
$form_code_type = $_POST['form_code_type'];
?>

<?php html_header_show(); ?>

<?php
if ($codetype) {
    echo "<input type='text' name='form_code_type' value='$codetype' size='5' readonly>\n";
} else {
    echo "   <select name='form_code_type'";
    echo ">\n";
    foreach ($code_types as $key => $value) {
        echo "    <option value='$key'";
        if ($codetype == $key || $form_code_type == $key) {
            echo " selected";
        }

        echo ">$key</option>\n";
    }

    echo "    <option value='PROD'";
    if ($codetype == 'PROD' || $form_code_type == 'PROD') {
        echo " selected";
    }

    echo ">Product</option>\n";
    echo "   </select>&nbsp;&nbsp;\n";
}
?>
    <?php xl('Search for', 'e'); ?>

<?php if ($_REQUEST['bn_search']) {
    $search_term = $_REQUEST['search_term'];
    if ($form_code_type == 'PROD') {
        $query = "SELECT dt.drug_id, dt.selector, d.name " .
        "FROM drug_templates AS dt, drugs AS d WHERE " .
        "( d.name LIKE '%$search_term%' OR " .
        "dt.selector LIKE '%$search_term%' ) " .
        "AND d.drug_id = dt.drug_id " .
        "ORDER BY d.name, dt.selector, dt.drug_id";
        $res = sqlStatement($query);
        $row_count = 0;
        while ($row = sqlFetchArray($res)) {
            $row_count = $row_count + 1;
            $drug_id = addslashes($row['drug_id']);
            $selector = addslashes($row['selector']);
            $desc = addslashes($row['name']);
            ?>
             <input type="checkbox" name="diagnosis[row_count]" value= "<?php echo $desc; ?>" > <?php echo $drug_id."    ".$selector."     ".$desc."</br>";
        }
    } else {
        $query = "SELECT count(*) as count FROM codes " .
        "WHERE (code_text LIKE '%$search_term%' OR " .
        "code LIKE '%$search_term%') " ;
        $res = sqlStatement($query);
        if ($row = sqlFetchArray($res)) {
            $no_of_items = addslashes($row['count']);
            if ($no_of_items < 1) {
                ?>
             <script language='JavaScript'>
            alert("<?php echo xl('Search string does not match with list in database');
            echo '\n';
            echo xl('Please enter new search string');?>");
          document.theform.search_term.value=" ";
             document.theform.search_term.focus();
             </script>
                <?php
            }

            $query = "SELECT code_type, code, modifier, code_text FROM codes " .
            "WHERE (code_text LIKE '%$search_term%' OR " .
            "code LIKE '%$search_term%') " .
            "ORDER BY code";
          // echo "\n<!-- $query -->\n"; // debugging
            $res = sqlStatement($query);
            $row_count = 0;
            while ($row = sqlFetchArray($res)) {
                $row_count = $row_count + 1;
                $itercode = addslashes($row['code']);
                $itertext = addslashes(ucfirst(strtolower(trim($row['code_text']))));
                ?>
                 <input type="checkbox" id="chkbox" value= "<?php echo $form_code_type.":".$itercode."-".$itertext; ?>" > <?php echo $itercode."    ".$itertext."</br>";
            }
        }
    }
    ?>
  </td>
 </tr>
 </table>
<center>
</br>
 <input type='button' id='select_all' value='<?php xl('Select All', 'e'); ?>' onclick="chkbox_select_all(document.select_diagonsis.chkbox);"/>

 <input type='button' id='unselect_all' value='<?php xl('Unselect All', 'e'); ?>' onclick="chkbox_select_none(document.select_diagonsis.chkbox);"/>

 <input type='button' id='submit' value='<?php xl('Submit', 'e'); ?>' onclick="window_submit(document.select_diagonsis.chkbox);"/>

 <input type='button' id='cancel' value='<?php xl('Cancel', 'e'); ?>' onclick="window_close();"/>

</center>
<?php } ?>
</form>
</body>
</html>
