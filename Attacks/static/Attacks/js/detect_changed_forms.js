$(function update_textarea_content() {
    $('#id_xmlb-xmlb_type').on("change", function (e, data){
        var xmlb_type_selected = $(this).children(":selected").attr("value");
        if (xmlb_type_selected === 'BIL') {
            $('#xmlbext_payload')[0].style.display= "none";
            $('#xmlbint_payload')[0].style.display= "none";
            $('#num_entities')[0].style.display= "block";
            $('#num_recursion')[0].style.display= "block";
            $('#xmlbbil_payload')[0].style.display= "block";
        }
        else if (xmlb_type_selected === 'ExtEnt'){
            $('#xmlbbil_payload')[0].style.display= "none";
            $('#num_entities')[0].style.display= "none";
            $('#num_recursion')[0].style.display= "none";
            $('#xmlbint_payload')[0].style.display= "none";
            $('#xmlbext_payload')[0].style.display= "block";
        }
        else {
            $('#xmlbext_payload')[0].style.display= "none";
            $('#xmlbbil_payload')[0].style.display= "none";
            $('#num_entities')[0].style.display= "none";
            $('#num_recursion')[0].style.display= "none";
            $('#xmlbint_payload')[0].style.display= "block";
        }
    });
    $('#id_sqli-sqli_type').on("change", function (e, data){
        var sqli_type_selected = $(this).children(":selected").attr("value");
        if (sqli_type_selected === 'Taut') {
            $('#union_patterns')[0].style.display= "none";
            $('#num_union')[0].style.display= "none";
            $('#piggyb_patterns')[0].style.display= "none";
            $('#num_piggyb')[0].style.display= "none";
            $('#incq_patterns')[0].style.display= "none";
            $('#num_incq')[0].style.display= "none";
            $('#tauto_patterns')[0].style.display= "block";
            $('#num_taut')[0].style.display= "block";
        }
        else if (sqli_type_selected === 'Union'){
            $('#tauto_patterns')[0].style.display= "none";
            $('#num_taut')[0].style.display= "none";
            $('#incq_patterns')[0].style.display= "none";
            $('#num_incq')[0].style.display= "none";
            $('#piggyb_patterns')[0].style.display= "none";
            $('#num_piggyb')[0].style.display= "none";
            $('#union_patterns')[0].style.display= "block";
            $('#num_union')[0].style.display= "block";
        }
        else if (sqli_type_selected === 'PiggyB') {
            $('#tauto_patterns')[0].style.display= "none";
            $('#num_taut')[0].style.display= "none";
            $('#union_patterns')[0].style.display= "none";
            $('#num_union')[0].style.display= "none";
            $('#incq_patterns')[0].style.display= "none";
            $('#num_incq')[0].style.display= "none";
            $('#piggyb_patterns')[0].style.display= "block";
            $('#num_piggyb')[0].style.display= "block";
        }
        else if (sqli_type_selected === 'IncQ') {
            $('#tauto_patterns')[0].style.display= "none";
            $('#num_taut')[0].style.display= "none";
            $('#union_patterns')[0].style.display= "none";
            $('#num_union')[0].style.display= "none";
            $('#piggyb_patterns')[0].style.display= "none";
            $('#num_piggyb')[0].style.display= "none";
            $('#incq_patterns')[0].style.display= "block";
            $('#num_incq')[0].style.display= "block";
        }
    });
    $('#id_overxml-oversized_xml_type').on("change", function (e, data) {
        var oversized_xml_type_selected = $(this).children(":selected").attr("value");
        if (oversized_xml_type_selected === 'OverAttrContent') {
            $('#extra_long_names_payload')[0].style.display = "none";
            $('#oversized_attribute_content_payload')[0].style.display = "block";
            $('#number_characters')[0].style.display= "block";
        }
        else if (oversized_xml_type_selected === 'LongNames') {
            $('#extra_long_names_payload')[0].style.display = "block";
            $('#oversized_attribute_content_payload')[0].style.display = "none";
            $('#number_characters')[0].style.display= "block";
        }
    });
    if (document.getElementById('id_overpayload-oversized_payload_type').value === 'Body')
    {
        $('#body_payload')[0].style.display = "block";
    }
    else {
        $('#id_overpayload-oversized_payload_type').on("change", function (e, data) {
            var oversized_payload_type_selected = $(this).children(":selected").attr("value");
            if (oversized_payload_type_selected === 'Header') {
                $('#body_payload')[0].style.display = "none";
                $('#envelope_payload')[0].style.display = "none";
                $('#header_payload')[0].style.display = "block";
                $('#number_characters')[0].style.display = "block";
            }
            else if (oversized_payload_type_selected === 'Body') {
                $('#body_payload')[0].style.display = "block";
                $('#envelope_payload')[0].style.display = "none";
                $('#header_payload')[0].style.display = "none";
                $('#number_characters')[0].style.display = "block";
            }
            else if (oversized_payload_type_selected === 'Envelope') {
                $('#body_payload')[0].style.display = "none";
                $('#envelope_payload')[0].style.display = "block";
                $('#header_payload')[0].style.display = "none";
                $('#number_characters')[0].style.display = "block";
            }
        });
    }
    $('#id_xmli-xml_injection_type').on("change", function (e, data) {
        var xml_injection_type_selected = $(this).children(":selected").attr("value");
        if (xml_injection_type_selected === 'Malformed') {
            $('#deforming_patterns')[0].style.display = "block";
            $('#random_closing_tags_patterns')[0].style.display = "block";
            //$('#special_values_patterns')[0].style.display= "block";
            $('#nested_sql_patterns')[0].style.display = "none";
            $('#nested_xpath_patterns')[0].style.display = "none";
            $('#number_deforming')[0].style.display = "block";
            $('#number_random_closing_tags')[0].style.display = "block";
            //$('#number_special_values')[0].style.display = "block";
            $('#number_nested_sql')[0].style.display = "none";
            $('#number_nested_xpath')[0].style.display = "none";
        }
        else if (xml_injection_type_selected === 'Replicating') {
            $('#deforming_patterns')[0].style.display = "block";
            $('#random_closing_tags_patterns')[0].style.display = "block";
            //$('#special_values_patterns')[0].style.display= "block";
            $('#nested_sql_patterns')[0].style.display = "block";
            $('#nested_xpath_patterns')[0].style.display = "block";
            $('#number_deforming')[0].style.display = "block";
            $('#number_random_closing_tags')[0].style.display = "block";
            //$('#number_special_values')[0].style.display = "block";
            $('#number_nested_sql')[0].style.display = "block";
            $('#number_nested_xpath')[0].style.display = "block";
        }
        else if (xml_injection_type_selected === 'XPath') {
            $('#deforming_patterns')[0].style.display = "none";
            $('#random_closing_tags_patterns')[0].style.display = "none";
            //$('#special_values_patterns')[0].style.display= "none";
            $('#nested_sql_patterns')[0].style.display = "none";
            $('#nested_xpath_patterns')[0].style.display = "block";
            $('#number_deforming')[0].style.display = "none";
            $('#number_random_closing_tags')[0].style.display = "none";
            //$('#number_special_values')[0].style.display = "none";
            $('#number_nested_sql')[0].style.display = "none";
            $('#number_nested_xpath')[0].style.display = "block";
        }

    });
});


