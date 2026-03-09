import requests
from datetime import datetime, timedelta
import os
import re
from dotenv import load_dotenv

load_dotenv()

class ValidationEngine:
    def __init__(self):
    # Fix the API URL - read from environment variables
        self.api_url = os.getenv('REDCAP_API_URL', '')
        self.api_token = os.getenv('REDCAP_API_TOKEN', '')
        self.rules = []
        self.setup_default_rules()
        
        # Print status
        if not self.api_url or not self.api_token:
            print("⚠️  REDCap API not configured. Using mock data for testing.")
        else:
            print(f"✅ REDCap API configured: {self.api_url}")
    
    def add_rule(self, field, validation_func, error_msg, suggestion, severity='Warning'):
        self.rules.append({
            'field': field,
            'func': validation_func,
            'error_msg': error_msg,
            'suggestion': suggestion,
            'severity': severity
        })
    def setup_default_rules(self):
        
        
        # =========================================================================
        # MATERNAL REGISTRATION FORM - BASIC INFO & IDS (Rules 1-30)
        # =========================================================================
        
            # Rule 1: CHAMPS ID must be exactly 9 digits
            self.add_rule(
                field='champs_id_ps',
                validation_func=lambda x: len(str(x).strip()) == 9 if x and str(x).strip() else True,
                error_msg='CHAMPS ID must be exactly 9 digits',
                suggestion='Enter a valid 9-digit CHAMPS ID (e.g., 123456789)',
                severity='Critical'
            )
            
            # Rule 2: Version of data specifications must be 1.0.0
            self.add_rule(
                field='versionofdataspecification',
                validation_func=lambda x: str(x).strip() == '1.0.0' if x and str(x).strip() else True,
                error_msg='Version must be 1.0.0',
                suggestion='Set version to 1.0.0 as per default',
                severity='Info'
            )
            
            # Rule 3: Alternate ID length validation (max 50 chars)
            self.add_rule(
                field='alt_mom_id_reg',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Alternate ID exceeds maximum length of 50 characters',
                suggestion='Truncate or verify the alternate ID',
                severity='Warning'
            )
            
            # Rule 4: Primary phone number length validation (max 10 digits)
            self.add_rule(
                field='phone_primary',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Phone number exceeds maximum length of 10 digits',
                suggestion='Remove dashes and ensure number is not longer than 10 digits',
                severity='Warning'
            )
            
            # Rule 5: Primary phone number format (digits only after cleaning)
            self.add_rule(
                field='phone_primary',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Phone number should contain only digits',
                suggestion='Remove any non-digit characters and enter a valid phone number',
                severity='Warning'
            )
            
            # Rule 6: Primary address should not be empty
            self.add_rule(
                field='address_primary',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Primary address is required',
                suggestion='Enter the current address',
                severity='Critical'
            )
            
            # Rule 7: Catchment ID must be 1, 2, or 3
            self.add_rule(
                field='catchment_idreg',
                validation_func=lambda x: x in ['1', '2', '3'] if x and str(x).strip() else True,
                error_msg='Invalid catchment ID',
                suggestion='Select 1=Harar, 2=Haramaya, or 3=Kersa',
                severity='Critical'
            )
            
            # Rule 8: Harar health facility must be valid
            self.add_rule(
                field='errors_hc',
                validation_func=lambda x: x in ['H01', 'H02', 'H03', 'H04', 'H05', 'H06', 'H07'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid health facility for Harar',
                suggestion='Select from H01-H07',
                severity='Critical'
            )
            
            # Rule 9: Haramaya health facility must be valid
            self.add_rule(
                field='error_hc_hrm',
                validation_func=lambda x: x in ['HY01', 'HY02', 'HY03', 'HY04', 'HY05', 'HY06', 'HY07'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid health facility for Haramaya',
                suggestion='Select from HY01-HY07',
                severity='Critical'
            )
            
            # Rule 10: Kersa health facility must be valid
            self.add_rule(
                field='errors_hcw',
                validation_func=lambda x: x in ['HK01', 'HK02', 'HK03', 'HK04', 'HK05', 'HK06'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid health facility for Kersa',
                suggestion='Select from HK01-HK06',
                severity='Critical'
            )
            
            # Rule 11: Haramaya sub-district validation (F01-F12)
            self.add_rule(
                field='subdis_har',
                validation_func=lambda x: x in ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid Haramaya sub-district',
                suggestion='Select from F01-F12',
                severity='Critical'
            )
            
            # Rule 12: Harar sub-district validation (H01-H18)
            self.add_rule(
                field='subdis_rar',
                validation_func=lambda x: x in ['17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid Harar sub-district',
                suggestion='Select from H01-H18',
                severity='Critical'
            )
            
            # Rule 13: Kersa sub-district validation (K01-K24)
            self.add_rule(
                field='subdis_ker',
                validation_func=lambda x: x in ['29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', 
                                            '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid Kersa sub-district',
                suggestion='Select from K01-K24',
                severity='Critical'
            )
            
            # Rule 14: F01 village code validation
            self.add_rule(
                field='villcode_har_f01',
                validation_func=lambda x: x in ['53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64',
                                            '65', '66', '67', '68', '69', '70', '71', '72', '73', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F01 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 15: F02 village code validation
            self.add_rule(
                field='villcode_har_f02',
                validation_func=lambda x: x in ['74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85',
                                            '86', '87', '88', '89', '90', '91', '92', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F02 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 16: F03 village code validation
            self.add_rule(
                field='villcode_har_f03',
                validation_func=lambda x: x in ['93', '94', '95', '96', '97', '98', '99', '100', '101', '102', '103', '104',
                                            '105', '106', '107', '108', '109', '110', '111', '112', '113', '114', '115', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F03 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 17: F04 village code validation
            self.add_rule(
                field='villcode_har_f04',
                validation_func=lambda x: x in ['116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '127', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F04 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 18: F05 village code validation
            self.add_rule(
                field='villcode_har_f05',
                validation_func=lambda x: x in ['128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138',
                                            '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F05 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 19: F06 village code validation
            self.add_rule(
                field='villcode_har_f06',
                validation_func=lambda x: x in ['150', '151', '152', '153', '154', '155', '156', '157', '158', '159', '160',
                                            '161', '162', '163', '164', '165', '166', '167', '168', '169', '170', '171',
                                            '172', '173', '174', '175', '176', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F06 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 20: F07 village code validation
            self.add_rule(
                field='villcode_har_f07',
                validation_func=lambda x: x in ['177', '178', '179', '180', '181', '182', '183', '184', '185', '186', '187',
                                            '188', '189', '190', '191', '192', '193', '194', '195', '196', '197', '198',
                                            '199', '200', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F07 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 21: F08 village code validation
            self.add_rule(
                field='villcode_har_f08',
                validation_func=lambda x: x in ['201', '202', '203', '204', '205', '206', '207', '208', '209', '210', '211',
                                            '212', '213', '214', '215', '216', '217', '218', '219', '220', '221', '222',
                                            '223', '224', '225', '226', '227', '228', '229', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F08 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 22: F09 village code validation
            self.add_rule(
                field='villcode_har_f09',
                validation_func=lambda x: x in ['230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240',
                                            '241', '242', '243', '244', '245', '246', '247', '248', '249', '250', '251',
                                            '252', '253', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F09 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 23: F10 village code validation
            self.add_rule(
                field='villcode_har_f10',
                validation_func=lambda x: x in ['254', '255', '256', '257', '258', '259', '260', '261', '262', '263', '264',
                                            '265', '266', '267', '268', '269', '270', '271', '272', '273', '274', '275',
                                            '276', '277', '278', '279', '280', '281', '282', '283', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F10 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 24: F11 village code validation
            self.add_rule(
                field='villcode_har_f11',
                validation_func=lambda x: x in ['284', '285', '286', '287', '288', '289', '290', '291', '292', '293', '294',
                                            '295', '296', '297', '298', '299', '300', '301', '302', '303', '304', '305',
                                            '306', '307', '308', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid F11 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 25: F12 village code validation
            self.add_rule(
                field='villcode_har_f12',
                validation_func=lambda x: x in ['309', '310', '311', '999'] if x and str(x).strip() else True,
                error_msg='Invalid F12 village code',
                suggestion='Select 309, 310, 311, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 26: H01 village code validation
            self.add_rule(
                field='villcode_rar_h01',
                validation_func=lambda x: x in ['312', '339', '340', '341', '342', '343', '344', '345', '346', '347', '348',
                                            '349', '350', '351', '352', '353', '354', '355', '356', '357', '358', '359',
                                            '360', '361', '362', '363', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H01 village code',
                suggestion='Select A01-A26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 27: H02 village code validation
            self.add_rule(
                field='villcode_rar_h02',
                validation_func=lambda x: x in ['364', '365', '366', '367', '368', '369', '370', '371', '372', '373', '374',
                                            '375', '376', '377', '378', '379', '380', '381', '382', '383', '384', '385',
                                            '386', '387', '388', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H02 village code',
                suggestion='Select M01-M25 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 28: H04 village code validation
            self.add_rule(
                field='villcode_rar_h04',
                validation_func=lambda x: x in ['389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399',
                                            '400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H04 village code',
                suggestion='Select B01-B22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 29: H05 village code validation
            self.add_rule(
                field='villcode_rar_h05',
                validation_func=lambda x: x in ['411', '412', '413', '414', '415', '416', '417', '418', '419', '420', '421',
                                            '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432',
                                            '433', '434', '435', '436', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H05 village code',
                suggestion='Select D01-D26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 30: H08 village code validation
            self.add_rule(
                field='villcode_rar_h08',
                validation_func=lambda x: x in ['437', '438', '439', '440', '441', '442', '443', '444', '445', '446', '447',
                                            '448', '449', '450', '451', '452', '453', '454', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H08 village code',
                suggestion='Select S01-S18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 31: H10 village code validation
            self.add_rule(
                field='villcode_rar_h10',
                validation_func=lambda x: x in ['455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465',
                                            '466', '467', '468', '469', '470', '471', '472', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H10 village code',
                suggestion='Select W01-W18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 32: H12 village code validation
            self.add_rule(
                field='villcode_rar_h12',
                validation_func=lambda x: x in ['473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483',
                                            '484', '485', '486', '487', '488', '489', '490', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H12 village code',
                suggestion='Select C01-C18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 33: H13 village code validation
            self.add_rule(
                field='villcode_rar_h13',
                validation_func=lambda x: x in ['491', '492', '493', '494', '495', '496', '497', '498', '499', '500', '501',
                                            '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '512', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H13 village code',
                suggestion='Select R01-R22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 34: H15 village code validation
            self.add_rule(
                field='villcode_rar_h15',
                validation_func=lambda x: x in ['513', '514', '515', '516', '517', '518', '519', '520', '521', '522', '523',
                                            '524', '525', '526', '527', '528', '529', '530', '531', '532', '533', '534',
                                            '535', '536', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H15 village code',
                suggestion='Select J01-J24 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 35: H16 village code validation
            self.add_rule(
                field='villcode_rar_h16',
                validation_func=lambda x: x in ['537', '538', '539', '540', '541', '542', '543', '544', '545', '546', '547',
                                            '548', '549', '550', '551', '552', '553', '554', '555', '556', '557', '558', '559', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H16 village code',
                suggestion='Select N01-N23 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 36: H17 village code validation
            self.add_rule(
                field='villcode_rar_h17',
                validation_func=lambda x: x in ['560', '561', '562', '563', '564', '565', '566', '567', '568', '569', '570',
                                            '571', '572', '573', '574', '575', '576', '577', '578', '579', '580', '581',
                                            '582', '583', '584', '585', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H17 village code',
                suggestion='Select I01-I26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 37: H18 village code validation
            self.add_rule(
                field='villcode_rar_h18',
                validation_func=lambda x: x in ['586', '587', '588', '589', '590', '591', '592', '593', '594', '595', '596',
                                            '597', '598', '599', '600', '601', '602', '603', '604', '605', '606', '607', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid H18 village code',
                suggestion='Select E01-E22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 38: K01 village code validation
            self.add_rule(
                field='villcode_ker_k01',
                validation_func=lambda x: x in ['608', '609', '610', '611', '612', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K01 village code',
                suggestion='Select KE0, KEA, KEB, KEC, KED, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 39: K02 village code validation
            self.add_rule(
                field='villcode_ker_k02',
                validation_func=lambda x: x in ['613', '614', '615', '616', '617', '618', '619', '620', '621', '622', '623',
                                            '624', '625', '626', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K02 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 40: K03 village code validation
            self.add_rule(
                field='villcode_ker_k03',
                validation_func=lambda x: x in ['627', '628', '629', '630', '631', '632', '633', '634', '635', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K03 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 41: K04 village code validation
            self.add_rule(
                field='villcode_ker_k04',
                validation_func=lambda x: x in ['636', '637', '638', '639', '640', '641', '642', '643', '644', '645', '646', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K04 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 42: K05 village code validation
            self.add_rule(
                field='villcode_ker_k05',
                validation_func=lambda x: x in ['647', '648', '649', '650', '651', '652', '653', '654', '655', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K05 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 43: K06 village code validation
            self.add_rule(
                field='villcode_ker_k06',
                validation_func=lambda x: x in ['656', '657', '658', '659', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K06 village code',
                suggestion='Select GEB, GEC, GED, GEE, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 44: K07 village code validation
            self.add_rule(
                field='villcode_ker_k07',
                validation_func=lambda x: x in ['660', '661', '662', '663', '664', '665', '666', '667', '668', '669', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K07 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 45: K08 village code validation
            self.add_rule(
                field='villcode_ker_k08',
                validation_func=lambda x: x in ['670', '671', '672', '673', '674', '675', '676', '677', '678', '679', '680', '681', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K08 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 46: K09 village code validation
            self.add_rule(
                field='villcode_ker_k09',
                validation_func=lambda x: x in ['682', '683', '684', '685', '686', '687', '688', '689', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K09 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 47: K10 village code validation
            self.add_rule(
                field='villcode_ker_k10',
                validation_func=lambda x: x in ['690', '691', '692', '693', '694', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K10 village code',
                suggestion='Select ABE, BEB, BUR, KOT, MEA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 48: K11 village code validation
            self.add_rule(
                field='villcode_ker_k11',
                validation_func=lambda x: x in ['695', '696', '697', '698', '699', '700', '701', '702', '703', '704', '705',
                                            '706', '707', '708', '709', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K11 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 49: K12 village code validation
            self.add_rule(
                field='villcode_ker_k12',
                validation_func=lambda x: x in ['710', '711', '712', '713', '714', '715', '716', '717', '718', '719', '720',
                                            '721', '722', '723', '724', '725', '726', '727', '728', '729', '730', '731',
                                            '732', '733', '734', '735', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K12 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 50: K13 village code validation
            self.add_rule(
                field='villcode_ker_k13',
                validation_func=lambda x: x in ['736', '737', '738', '739', '740', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K13 village code',
                suggestion='Select KE1-KE5 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 51: K14 village code validation
            self.add_rule(
                field='villcode_ker_k14',
                validation_func=lambda x: x in ['741', '742', '743', '744', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K14 village code',
                suggestion='Select ALI, BEY, GOC, TUA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 52: K15 village code validation
            self.add_rule(
                field='villcode_ker_k15',
                validation_func=lambda x: x in ['745', '746', '747', '748', '749', '750', '751', '752', '753', '754', '755', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K15 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 53: K16 village code validation
            self.add_rule(
                field='villcode_ker_k16',
                validation_func=lambda x: x in ['756', '757', '758', '759', '760', '761', '762', '763', '764', '765', '766',
                                            '767', '768', '769', '770', '771', '772', '773', '774', '775', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K16 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 54: K17 village code validation
            self.add_rule(
                field='villcode_ker_k17',
                validation_func=lambda x: x in ['776', '777', '778', '779', '780', '781', '782', '783', '784', '785', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K17 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 55: K18 village code validation
            self.add_rule(
                field='villcode_ker_k18',
                validation_func=lambda x: x in ['786', '787', '788', '789', '790', '791', '792', '793', '794', '795', '796',
                                            '797', '798', '799', '800', '801', '802', '803', '804', '805', '806', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K18 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 56: K19 village code validation
            self.add_rule(
                field='villcode_ker_k19',
                validation_func=lambda x: x in ['807', '808', '809', '810', '811', '812', '813', '814', '815', '816', '817', '818', '819', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K19 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 57: K20 village code validation
            self.add_rule(
                field='villcode_ker_k20',
                validation_func=lambda x: x in ['820', '821', '822', '823', '824', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K20 village code',
                suggestion='Select ABB, DEA, HAL, KOA, SOA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 58: K21 village code validation
            self.add_rule(
                field='villcode_ker_k21',
                validation_func=lambda x: x in ['825', '826', '827', '828', '829', '830', '831', '832', '833', '834', '835', '836', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K21 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 59: K22 village code validation
            self.add_rule(
                field='villcode_ker_k22',
                validation_func=lambda x: x in ['837', '838', '839', '840', '841', '842', '843', '844', '845', '846', '847',
                                            '848', '849', '850', '851', '852', '853', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K22 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 60: K23 village code validation
            self.add_rule(
                field='villcode_ker_k23',
                validation_func=lambda x: x in ['854', '855', '856', '857', '858', '999'] if x and str(x).strip() else True,
                error_msg='Invalid K23 village code',
                suggestion='Select ARB, GEK, SEK, WAD, WOR, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 61: K24 village code validation
            self.add_rule(
                field='villcode_ker_k24',
                validation_func=lambda x: x in ['859', '860', '861', '862', '863', '864', '865', '866', '867', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid K24 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 62: Other village specification required when 999 selected
            self.add_rule(
                field='vill_otherspecmr',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Village specification required when "Other" is selected',
                suggestion='Enter the village name',
                severity='Critical'
            )
            
            # Rule 63: Date of birth type must be valid
            self.add_rule(
                field='date_dob_mom_type',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid date of birth type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 64: Date of birth cannot be future
            self.add_rule(
                field='date_dob_mom',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Date of birth cannot be in the future',
                suggestion='Correct the date of birth',
                severity='Critical'
            )
            
            # Rule 65: Date of birth must be after 1900
            self.add_rule(
                field='date_dob_mom',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(1900, 1, 1) if x and str(x).strip() else True,
                error_msg='Date of birth is too early',
                suggestion='Verify the date of birth',
                severity='Warning'
            )
            
            # Rule 66: Birth country must be valid
            self.add_rule(
                field='birth_country_mom',
                validation_func=lambda x: x in ['CH00408', 'CH02624', 'CH02625', 'CH00409', 'CH02626', 'CH02627', 
                                            'CH02628', 'CH02629', 'CH02623', 'CH02630', 'CH02631', 'CH02632', 
                                            'CH00010', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid birth country code',
                suggestion='Select a valid country from the list',
                severity='Critical'
            )
            
            # Rule 67: Other country specification required when "Other" selected
            self.add_rule(
                field='birth_country_mom_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Country specification required when "Other" is selected',
                suggestion='Enter the country name',
                severity='Critical'
            )
            
            # Rule 68: Other country specification length
            self.add_rule(
                field='birth_country_mom_other',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Country specification exceeds 100 characters',
                suggestion='Shorten the country name',
                severity='Warning'
            )
            
            # Rule 69: Vocation must be valid
            self.add_rule(
                field='vocation',
                validation_func=lambda x: x in ['CH02335', 'CH02336', 'CH02337', 'CH02338', 'CH02339', 'CH02340', 
                                            'CH02341', 'CH00010'] if x and str(x).strip() else True,
                error_msg='Invalid vocation code',
                suggestion='Select a valid occupation',
                severity='Critical'
            )
            
            # Rule 70: Other vocation specification required when "Other" selected
            self.add_rule(
                field='vocation_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Occupation specification required when "Other" is selected',
                suggestion='Enter the occupation',
                severity='Critical'
            )
            
            # Rule 71: Other vocation length
            self.add_rule(
                field='vocation_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Occupation exceeds 50 characters',
                suggestion='Shorten the occupation description',
                severity='Warning'
            )
            
            # Rule 72: Cooking method 1 must be valid
            self.add_rule(
                field='cook_method_1',
                validation_func=lambda x: x in ['CH02349', 'CH02350', 'CH02343', 'CH02344', 'CH02345', 'CH02346', 
                                            'CH02347', 'CH02348', 'CH02351', 'CH02352', 'CH00010', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid cooking method',
                suggestion='Select a valid cooking method',
                severity='Critical'
            )
            
            # Rule 73: Other cooking method 1 specification required when "Other" selected
            self.add_rule(
                field='cook_method_1_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Cooking method specification required when "Other" is selected',
                suggestion='Enter the cooking method',
                severity='Critical'
            )
            
            # Rule 74: Other cooking method 1 length
            self.add_rule(
                field='cook_method_1_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Cooking method exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 75: Cooking fuel must be valid
            self.add_rule(
                field='cook_method_1_fuel',
                validation_func=lambda x: x in ['CH02358', 'CH02354', 'CH02355', 'CH02356', 'CH02357', 'CH02359', 
                                            'CH02360', 'CH02361', 'CH02362', 'CH02363', 'CH02364', 'CH02365',
                                            'CH02366', 'CH02367', 'CH02368', 'CH00010', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid fuel type',
                suggestion='Select a valid fuel type',
                severity='Critical'
            )
            
            # Rule 76: Other fuel specification required when "Other" selected
            self.add_rule(
                field='cook_method_1_fuel_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Fuel specification required when "Other" is selected',
                suggestion='Enter the fuel type',
                severity='Critical'
            )
            
            # Rule 77: Other fuel length
            self.add_rule(
                field='cook_method_1_fuel_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Fuel specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 78: Cook other must be valid
            self.add_rule(
                field='cookother',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for another cookstove',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 79: Cooking method 2 must be valid
            self.add_rule(
                field='cook_method_2',
                validation_func=lambda x: x in ['CH02349', 'CH02350', 'CH02343', 'CH02344', 'CH02345', 'CH02346', 
                                            'CH02347', 'CH02348', 'CH02351', 'CH02352', 'CH00010', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid second cooking method',
                suggestion='Select a valid cooking method',
                severity='Critical'
            )
            
            # Rule 80: Other cooking method 2 specification required when "Other" selected
            self.add_rule(
                field='cook_method_2_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Second cooking method specification required when "Other" is selected',
                suggestion='Enter the cooking method',
                severity='Critical'
            )
            
            # Rule 81: Other cooking method 2 length
            self.add_rule(
                field='cook_method_2_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Cooking method exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 82: Cooking fuel 2 must be valid
            self.add_rule(
                field='cook_method_2_fuel',
                validation_func=lambda x: x in ['CH02358', 'CH02354', 'CH02355', 'CH02356', 'CH02357', 'CH02359', 
                                            'CH02360', 'CH02361', 'CH02362', 'CH02363', 'CH02364', 'CH02365',
                                            'CH02366', 'CH02367', 'CH00010', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid second fuel type',
                suggestion='Select a valid fuel type',
                severity='Critical'
            )
            
            # Rule 83: Other fuel 2 specification required when "Other" selected
            self.add_rule(
                field='cook_method_2_fuel_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Second fuel specification required when "Other" is selected',
                suggestion='Enter the fuel type',
                severity='Critical'
            )
            
            # Rule 84: Other fuel 2 length
            self.add_rule(
                field='cook_method_2_fuel_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Fuel specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 85: Cooking location must be valid
            self.add_rule(
                field='cook_location',
                validation_func=lambda x: x in ['CH02369', 'CH02370', 'CH02371'] if x and str(x).strip() else True,
                error_msg='Invalid cooking location',
                suggestion='Select In house, Separate building, or Outdoors',
                severity='Warning'
            )
            
            # Rule 86: Separate kitchen must be valid
            self.add_rule(
                field='cook_location_room',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for separate kitchen',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 87: Cooking majority must be valid
            self.add_rule(
                field='cook_majority',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for cooking majority',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 88: Alternate contact 1 must be valid
            self.add_rule(
                field='alt_contact_1',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for alternate contact',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 89: Contact 1 name should not be empty when yes
            self.add_rule(
                field='contact_alt_1',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Alternate contact name required',
                suggestion='Enter the contact name',
                severity='Critical'
            )
            
            # Rule 90: Contact 1 phone length
            self.add_rule(
                field='contact_alt_1_phone',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Contact 1 phone exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 91: Contact 1 phone format
            self.add_rule(
                field='contact_alt_1_phone',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Contact 1 phone must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 92: Alternate contact 2 must be valid
            self.add_rule(
                field='alt_contact_2',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for second alternate contact',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 93: Contact 2 name should not be empty when yes
            self.add_rule(
                field='contact_alt_2',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Second alternate contact name required',
                suggestion='Enter the contact name',
                severity='Critical'
            )
            
            # Rule 94: Contact 2 phone length
            self.add_rule(
                field='contact_alt_2_phone',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Contact 2 phone exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 95: Contact 2 phone format
            self.add_rule(
                field='contact_alt_2_phone',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Contact 2 phone must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 96: Alternate contact 3 must be valid
            self.add_rule(
                field='alt_contact_3',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for third alternate contact',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 97: Contact 3 name should not be empty when yes
            self.add_rule(
                field='contact_alt_3',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Third alternate contact name required',
                suggestion='Enter the contact name',
                severity='Critical'
            )
            
            # Rule 98: Contact 3 phone length
            self.add_rule(
                field='contact_alt_3_phone',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Contact 3 phone exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 99: Contact 3 phone format
            self.add_rule(
                field='contact_alt_3_phone',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Contact 3 phone must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 100: Registration form completion date cannot be future
            self.add_rule(
                field='date_form_complete_reg',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Registration form completion date cannot be future',
                suggestion='Correct the date',
                severity='Critical'
            )
            
            # Rule 101: Prenatal context with registration must be valid
            self.add_rule(
                field='context_pre_to_reg',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for form completion timing with registration',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 102: Prenatal context with Day 01 must be valid
            self.add_rule(
                field='context_pre_to_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for form completion timing with Day 01',
                suggestion='Select Yes or No',
                severity='Warning'
            )

            # Rule 101: Prenatal context with registration must be valid
            self.add_rule(
                field='context_pre_to_reg',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for form completion timing with registration',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 102: Prenatal context with Day 01 must be valid
            self.add_rule(
                field='context_pre_to_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for form completion timing with Day 01',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 103: Interviewer ID is required
            self.add_rule(
                field='interviewer_id_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewer ID is required',
                suggestion='Enter the interviewer ID',
                severity='Critical'
            )
            
            # Rule 104: Interviewee is mother must be valid
            self.add_rule(
                field='interview_mom_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for interviewee being the mother',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 105: Interviewee name required when not mother
            self.add_rule(
                field='interviewee_name',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewee name is required when interviewee is not the mother',
                suggestion='Enter the name of the person being interviewed',
                severity='Critical'
            )
            
            # Rule 106: Husband relationship selected
            # This is a checkbox field - handled by existence check
            
            # Rule 107: Child relationship selected
            # Checkbox field
            
            # Rule 108: Mother relationship selected
            # Checkbox field
            
            # Rule 109: Father relationship selected
            # Checkbox field
            
            # Rule 110: Mother-in-law relationship selected
            # Checkbox field
            
            # Rule 111: Father-in-law relationship selected
            # Checkbox field
            
            # Rule 112: Aunt/Uncle relationship selected
            # Checkbox field
            
            # Rule 113: Cousin relationship selected
            # Checkbox field
            
            # Rule 114: Other relationship specification required when selected
            self.add_rule(
                field='intview_relation_oth_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Relationship specification required when "Other" is selected',
                suggestion='Specify the relationship to the woman',
                severity='Critical'
            )
            
            # Rule 115: Other relationship length
            self.add_rule(
                field='intview_relation_oth_pre',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Relationship specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 116: Address change must be valid
            self.add_rule(
                field='address_chg_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for address change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 117: Updated address should not be empty when changed
            self.add_rule(
                field='address_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Updated address is required when address changed',
                suggestion='Enter the new address',
                severity='Critical'
            )
            
            # Rule 118: Phone change must be valid
            self.add_rule(
                field='phone_chg_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for phone change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 119: Updated phone number length
            self.add_rule(
                field='phone_prenatal',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Updated phone number exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 120: Updated phone number format
            self.add_rule(
                field='phone_prenatal',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Updated phone number must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 121: Past pregnancy must be valid
            self.add_rule(
                field='past_pregnancy',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for past pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 122: Twin delivery must be valid
            self.add_rule(
                field='errors_twinpre',
                validation_func=lambda x: x in ['1', '2'] if x and str(x).strip() else True,
                error_msg='Invalid response for twin delivery',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 123: Total previous pregnancies must be between 0-50
            self.add_rule(
                field='num_preg_total',
                validation_func=lambda x: 0 <= int(x) <= 50 if x and str(x).strip() else True,
                error_msg='Total previous pregnancies must be between 0 and 50',
                suggestion='Verify the total number of pregnancies',
                severity='Warning'
            )
            
            # Rule 124: Number of miscarriages cannot be negative
            self.add_rule(
                field='num_misc_abort',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of miscarriages cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 125: Number of miscarriages cannot exceed total pregnancies
            # This requires cross-field validation - will be handled in validate_record method
            
            # Rule 126: Number of stillbirths cannot be negative
            self.add_rule(
                field='num_stillbirth',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of stillbirths cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 127: Number of premature stillbirths cannot be negative
            self.add_rule(
                field='num_stillbirth_pre',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of premature stillbirths cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 128: Number of full-term stillbirths cannot be negative
            self.add_rule(
                field='num_stillbirth_full',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of full-term stillbirths cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 129: Number of live births cannot be negative
            self.add_rule(
                field='num_live_birth',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of live births cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 130: Number of premature live births cannot be negative
            self.add_rule(
                field='num_live_birth_pre',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of premature live births cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 131: Number of full-term live births cannot be negative
            self.add_rule(
                field='num_live_birth_full',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of full-term live births cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 132: Number of neonatal deaths cannot be negative
            self.add_rule(
                field='num_neonate_death',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of neonatal deaths cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 133: Number of living children cannot be negative
            self.add_rule(
                field='num_children_live',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of living children cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 134: Number of child deaths cannot be negative
            self.add_rule(
                field='num_children_death',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of child deaths cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 135: Number of C-sections cannot be negative
            self.add_rule(
                field='num_csection',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Number of C-sections cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Critical'
            )
            
            # Rule 136: Heavy vaginal bleeding before pregnancy must be valid
            self.add_rule(
                field='hp_vbleed_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for heavy vaginal bleeding before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 137: Hypertension before pregnancy must be valid
            self.add_rule(
                field='hp_highbp_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for hypertension before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 138: Preeclampsia before pregnancy must be valid
            self.add_rule(
                field='hp_preclamp_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for preeclampsia before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 139: Eclampsia before pregnancy must be valid
            self.add_rule(
                field='hp_eclamp_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for eclampsia before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 140: Other seizures before pregnancy must be valid
            self.add_rule(
                field='hp_oth_seiz_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other seizures before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 141: Unplanned hospitalization before pregnancy must be valid
            self.add_rule(
                field='hp_uphosp_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for unplanned hospitalization before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 142: Hospitalization reason required when Yes selected
            self.add_rule(
                field='hp_uphosp_reason_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Reason for hospitalization required when "Yes" selected',
                suggestion='Specify the reason for hospitalization',
                severity='Critical'
            )
            
            # Rule 143: Hospitalization reason length
            self.add_rule(
                field='hp_uphosp_reason_pre',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Hospitalization reason exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 144: Trauma before pregnancy must be valid
            self.add_rule(
                field='hp_trauma_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for trauma before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 145: Trauma specification required when Yes selected
            self.add_rule(
                field='hp_trauma_specify_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Trauma specification required when "Yes" selected',
                suggestion='Specify the accident/assault/trauma',
                severity='Critical'
            )
            
            # Rule 146: Trauma specification length
            self.add_rule(
                field='hp_trauma_specify_pre',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Trauma specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 147: Malaria before pregnancy must be valid
            self.add_rule(
                field='hp_malaria_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for malaria before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 148: Diabetes before pregnancy must be valid
            self.add_rule(
                field='hp_diabetes_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for diabetes before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 149: Anemia before pregnancy must be valid
            self.add_rule(
                field='hp_anemia_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 150: HIV before pregnancy must be valid
            self.add_rule(
                field='hp_hiv_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for HIV before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 151: Mental health before pregnancy must be valid
            self.add_rule(
                field='hp_mental_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for mental health before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 152: COVID exposure before pregnancy must be valid
            self.add_rule(
                field='hp_covidex_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 153: COVID diagnosis before pregnancy must be valid
            self.add_rule(
                field='hp_covconfirm_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 154: Other health problem before pregnancy must be valid
            self.add_rule(
                field='hp_other_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem before pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 155: Other health problem specification required when Yes selected
            self.add_rule(
                field='hp_other_specify_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other health problem specification required when "Yes" selected',
                suggestion='Specify the other health problem',
                severity='Critical'
            )
            
            # Rule 156: Other health problem specification length
            self.add_rule(
                field='hp_other_specify_pre',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Health problem specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 157: Currently pregnant must be valid
            self.add_rule(
                field='currently_preg',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for current pregnancy status',
                suggestion='Select Yes or No',
                severity='Critical'
            )
            
            # Rule 158: Women in labor must be valid
            self.add_rule(
                field='errors_wmen_labor',
                validation_func=lambda x: x in ['1', '2'] if x and str(x).strip() else True,
                error_msg='Invalid response for current labor status',
                suggestion='Select Yes or No',
                severity='Critical'
            )
            
            # Rule 159: Planned delivery location must be valid
            self.add_rule(
                field='deliv_location_plan',
                validation_func=lambda x: x in ['CH00015', 'CH01840', 'CH02384', 'CH00010', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned delivery location',
                suggestion='Select from the list',
                severity='Critical'
            )
            
            # Rule 160: Planned delivery village catchment must be valid
            self.add_rule(
                field='deliv_vill_catch',
                validation_func=lambda x: x in ['1', '2', '3'] if x and str(x).strip() else True,
                error_msg='Invalid planned delivery catchment ID',
                suggestion='Select 1=Harar, 2=Haramaya, 3=Kersa',
                severity='Critical'
            )
            
            # Rule 161: Planned delivery sub-district for Haramaya must be valid
            self.add_rule(
                field='deliv_vill_sub_haramaya',
                validation_func=lambda x: x in ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned delivery sub-district for Haramaya',
                suggestion='Select from F01-F12',
                severity='Critical'
            )
            
            # Rule 162: Planned delivery F01 village must be valid
            self.add_rule(
                field='villcode_har_f01pre',
                validation_func=lambda x: x in ['53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64',
                                            '65', '66', '67', '68', '69', '70', '71', '72', '73', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F01 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 163: Planned delivery F02 village must be valid
            self.add_rule(
                field='villcode_har_f02pre',
                validation_func=lambda x: x in ['74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85',
                                            '86', '87', '88', '89', '90', '91', '92', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F02 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 164: Planned delivery F03 village must be valid
            self.add_rule(
                field='villcode_har_f03_pre',
                validation_func=lambda x: x in ['93', '94', '95', '96', '97', '98', '99', '100', '101', '102', '103', '104',
                                            '105', '106', '107', '108', '109', '110', '111', '112', '113', '114', '115', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F03 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 165: Planned delivery F04 village must be valid
            self.add_rule(
                field='villcode_har_f04_pre',
                validation_func=lambda x: x in ['116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '127', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F04 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 166: Planned delivery F05 village must be valid
            self.add_rule(
                field='villcode_har_f05_pre',
                validation_func=lambda x: x in ['128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138',
                                            '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F05 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 167: Planned delivery F06 village must be valid
            self.add_rule(
                field='villcode_har_f06_pre',
                validation_func=lambda x: x in ['150', '151', '152', '153', '154', '155', '156', '157', '158', '159', '160',
                                            '161', '162', '163', '164', '165', '166', '167', '168', '169', '170', '171',
                                            '172', '173', '174', '175', '176', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F06 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 168: Planned delivery F07 village must be valid
            self.add_rule(
                field='villcode_har_f07_pre',
                validation_func=lambda x: x in ['177', '178', '179', '180', '181', '182', '183', '184', '185', '186', '187',
                                            '188', '189', '190', '191', '192', '193', '194', '195', '196', '197', '198',
                                            '199', '200', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F07 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 169: Planned delivery F08 village must be valid
            self.add_rule(
                field='villcode_har_f08_pre',
                validation_func=lambda x: x in ['201', '202', '203', '204', '205', '206', '207', '208', '209', '210', '211',
                                            '212', '213', '214', '215', '216', '217', '218', '219', '220', '221', '222',
                                            '223', '224', '225', '226', '227', '228', '229', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F08 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 170: Planned delivery F09 village must be valid
            self.add_rule(
                field='villcode_har_f09_pre',
                validation_func=lambda x: x in ['230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240',
                                            '241', '242', '243', '244', '245', '246', '247', '248', '249', '250', '251',
                                            '252', '253', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F09 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 171: Planned delivery F10 village must be valid
            self.add_rule(
                field='villcode_har_f10_pre',
                validation_func=lambda x: x in ['254', '255', '256', '257', '258', '259', '260', '261', '262', '263', '264',
                                            '265', '266', '267', '268', '269', '270', '271', '272', '273', '274', '275',
                                            '276', '277', '278', '279', '280', '281', '282', '283', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F10 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 172: Planned delivery F11 village must be valid
            self.add_rule(
                field='villcode_har_f11_pre',
                validation_func=lambda x: x in ['284', '285', '286', '287', '288', '289', '290', '291', '292', '293', '294',
                                            '295', '296', '297', '298', '299', '300', '301', '302', '303', '304', '305',
                                            '306', '307', '308', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned F11 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 173: Planned delivery F12 village must be valid
            self.add_rule(
                field='villcode_har_f12_pre',
                validation_func=lambda x: x in ['309', '310', '311', '999'] if x and str(x).strip() else True,
                error_msg='Invalid planned F12 village code',
                suggestion='Select 309, 310, 311, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 174: Planned delivery sub-district for Harar must be valid
            self.add_rule(
                field='subdis_rar_pre',
                validation_func=lambda x: x in ['17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned delivery sub-district for Harar',
                suggestion='Select from H01-H18',
                severity='Critical'
            )
            
            # Rule 175: Planned delivery H01 village must be valid
            self.add_rule(
                field='villcode_rar_h01_pre',
                validation_func=lambda x: x in ['312', '339', '340', '341', '342', '343', '344', '345', '346', '347', '348',
                                            '349', '350', '351', '352', '353', '354', '355', '356', '357', '358', '359',
                                            '360', '361', '362', '363', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H01 village code',
                suggestion='Select A01-A26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 176: Planned delivery H02 village must be valid
            self.add_rule(
                field='villcode_rar_h02_pre',
                validation_func=lambda x: x in ['364', '365', '366', '367', '368', '369', '370', '371', '372', '373', '374',
                                            '375', '376', '377', '378', '379', '380', '381', '382', '383', '384', '385',
                                            '386', '387', '388', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H02 village code',
                suggestion='Select M01-M25 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 177: Planned delivery H04 village must be valid
            self.add_rule(
                field='villcode_rar_h04_pre',
                validation_func=lambda x: x in ['389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399',
                                            '400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H04 village code',
                suggestion='Select B01-B22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 178: Planned delivery H05 village must be valid
            self.add_rule(
                field='villcode_rar_h05_pre',
                validation_func=lambda x: x in ['411', '412', '413', '414', '415', '416', '417', '418', '419', '420', '421',
                                            '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432',
                                            '433', '434', '435', '436', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H05 village code',
                suggestion='Select D01-D26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 179: Planned delivery H08 village must be valid
            self.add_rule(
                field='villcode_rar_h08_pre',
                validation_func=lambda x: x in ['437', '438', '439', '440', '441', '442', '443', '444', '445', '446', '447',
                                            '448', '449', '450', '451', '452', '453', '454', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H08 village code',
                suggestion='Select S01-S18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 180: Planned delivery H10 village must be valid
            self.add_rule(
                field='villcode_rar_h10_pre',
                validation_func=lambda x: x in ['455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465',
                                            '466', '467', '468', '469', '470', '471', '472', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H10 village code',
                suggestion='Select W01-W18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 181: Planned delivery H12 village must be valid
            self.add_rule(
                field='villcode_rar_h12_pre',
                validation_func=lambda x: x in ['473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483',
                                            '484', '485', '486', '487', '488', '489', '490', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H12 village code',
                suggestion='Select C01-C18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 182: Planned delivery H13 village must be valid
            self.add_rule(
                field='villcode_rar_h13_pre',
                validation_func=lambda x: x in ['491', '492', '493', '494', '495', '496', '497', '498', '499', '500', '501',
                                            '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '512', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H13 village code',
                suggestion='Select R01-R22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 183: Planned delivery H15 village must be valid
            self.add_rule(
                field='villcode_rar_h15_pre',
                validation_func=lambda x: x in ['513', '514', '515', '516', '517', '518', '519', '520', '521', '522', '523',
                                            '524', '525', '526', '527', '528', '529', '530', '531', '532', '533', '534',
                                            '535', '536', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H15 village code',
                suggestion='Select J01-J24 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 184: Planned delivery H16 village must be valid
            self.add_rule(
                field='villcode_rar_h16_pre',
                validation_func=lambda x: x in ['537', '538', '539', '540', '541', '542', '543', '544', '545', '546', '547',
                                            '548', '549', '550', '551', '552', '553', '554', '555', '556', '557', '558', '559', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H16 village code',
                suggestion='Select N01-N23 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 185: Planned delivery H17 village must be valid
            self.add_rule(
                field='villcode_rar_h17_pre',
                validation_func=lambda x: x in ['560', '561', '562', '563', '564', '565', '566', '567', '568', '569', '570',
                                            '571', '572', '573', '574', '575', '576', '577', '578', '579', '580', '581',
                                            '582', '583', '584', '585', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H17 village code',
                suggestion='Select I01-I26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 186: Planned delivery H18 village must be valid
            self.add_rule(
                field='villcode_rar_h18_pre',
                validation_func=lambda x: x in ['586', '587', '588', '589', '590', '591', '592', '593', '594', '595', '596',
                                            '597', '598', '599', '600', '601', '602', '603', '604', '605', '606', '607', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned H18 village code',
                suggestion='Select E01-E22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 187: Planned delivery sub-district for Kersa must be valid
            self.add_rule(
                field='subdis_ker_pre',
                validation_func=lambda x: x in ['29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', 
                                            '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned delivery sub-district for Kersa',
                suggestion='Select from K01-K24',
                severity='Critical'
            )
            
            # Rule 188: Planned delivery K01 village must be valid
            self.add_rule(
                field='villcode_ker_k01_pre',
                validation_func=lambda x: x in ['608', '609', '610', '611', '612', '999'] if x and str(x).strip() else True,
                error_msg='Invalid planned K01 village code',
                suggestion='Select KE0, KEA, KEB, KEC, KED, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 189: Planned delivery K02 village must be valid
            self.add_rule(
                field='villcode_ker_k02_pre',
                validation_func=lambda x: x in ['613', '614', '615', '616', '617', '618', '619', '620', '621', '622', '623',
                                            '624', '625', '626', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K02 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 190: Planned delivery K03 village must be valid
            self.add_rule(
                field='villcode_ker_k03_pre',
                validation_func=lambda x: x in ['627', '628', '629', '630', '631', '632', '633', '634', '635', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K03 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 191: Planned delivery K04 village must be valid
            self.add_rule(
                field='villcode_ker_k04_pre',
                validation_func=lambda x: x in ['636', '637', '638', '639', '640', '641', '642', '643', '644', '645', '646', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K04 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 192: Planned delivery K05 village must be valid
            self.add_rule(
                field='villcode_ker_k05_pre',
                validation_func=lambda x: x in ['647', '648', '649', '650', '651', '652', '653', '654', '655', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K05 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 193: Planned delivery K06 village must be valid
            self.add_rule(
                field='villcode_ker_k06_pre',
                validation_func=lambda x: x in ['656', '657', '658', '659', '999'] if x and str(x).strip() else True,
                error_msg='Invalid planned K06 village code',
                suggestion='Select GEB, GEC, GED, GEE, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 194: Planned delivery K07 village must be valid
            self.add_rule(
                field='villcode_ker_k07_pre',
                validation_func=lambda x: x in ['660', '661', '662', '663', '664', '665', '666', '667', '668', '669', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K07 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 195: Planned delivery K08 village must be valid
            self.add_rule(
                field='villcode_ker_k08_pre',
                validation_func=lambda x: x in ['670', '671', '672', '673', '674', '675', '676', '677', '678', '679', '680', '681', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K08 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 196: Planned delivery K09 village must be valid
            self.add_rule(
                field='villcode_ker_k09_pre',
                validation_func=lambda x: x in ['682', '683', '684', '685', '686', '687', '688', '689', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K09 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 197: Planned delivery K10 village must be valid
            self.add_rule(
                field='villcode_ker_k10_pre',
                validation_func=lambda x: x in ['690', '691', '692', '693', '694', '999'] if x and str(x).strip() else True,
                error_msg='Invalid planned K10 village code',
                suggestion='Select ABE, BEB, BUR, KOT, MEA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 198: Planned delivery K11 village must be valid
            self.add_rule(
                field='villcode_ker_k11_pre',
                validation_func=lambda x: x in ['695', '696', '697', '698', '699', '700', '701', '702', '703', '704', '705',
                                            '706', '707', '708', '709', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K11 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 199: Planned delivery K12 village must be valid
            self.add_rule(
                field='villcode_ker_k12_pre',
                validation_func=lambda x: x in ['710', '711', '712', '713', '714', '715', '716', '717', '718', '719', '720',
                                            '721', '722', '723', '724', '725', '726', '727', '728', '729', '730', '731',
                                            '732', '733', '734', '735', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid planned K12 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 200: Other planned village specification required when 999 selected
            self.add_rule(
                field='vill_otherspecpre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other planned village specification required when "Other" is selected',
                suggestion='Specify the village name',
                severity='Critical'
            )
                # =============================================================================
    # BATCH 3: PRENATAL FORM - CURRENT PREGNANCY, MEASUREMENTS & ANC (Rules 201-300)
    # =============================================================================

        # Rule 201: Planned delivery facility must be valid
            self.add_rule(
                field='deliv_facility_plan',
                validation_func=lambda x: x in ['CH02648', 'CH02654', 'CH02652', 'CH02647', 'CH02646', 'CH01998',
                                            'CH02730', 'CH02651', 'CH02649', 'CH02650', 'CH02635', 'CH02637',
                                            'CH02634', 'CH02643', 'CH02642', 'CH02639', 'CH02640', 'CH02002',
                                            'CH02633', 'CH02638', 'CH02644', 'CH02636', 'CH02641', 'CH01995',
                                            'CH01996', 'CH01997', 'CH02007', 'CH02008', 'CH02009', 'CH02645',
                                            'CH01857', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid planned delivery facility',
                suggestion='Select a valid health facility from the list',
                severity='Critical'
            )
            
            # Rule 202: Other planned facility specification required when "Other" selected
            self.add_rule(
                field='deliv_facility_other_plan',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other planned facility specification required',
                suggestion='Specify the planned delivery facility',
                severity='Critical'
            )
            
            # Rule 203: Other planned facility length
            self.add_rule(
                field='deliv_facility_other_plan',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Planned facility specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 204: Other planned delivery location specification required
            self.add_rule(
                field='deliv_location_other_plan',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other planned delivery location specification required',
                suggestion='Specify the planned delivery location',
                severity='Critical'
            )
            
            # Rule 205: Other planned location length
            self.add_rule(
                field='deliv_location_other_plan',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Planned location specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 206: Estimated delivery must be valid
            self.add_rule(
                field='est_delivery',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for estimated delivery date',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 207: Estimated delivery date cannot be future
            self.add_rule(
                field='date_est_delivery',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Estimated delivery date cannot be in the future',
                suggestion='Correct the estimated delivery date',
                severity='Critical'
            )
            
            # Rule 208: Estimated delivery date must be after 2019
            self.add_rule(
                field='date_est_delivery',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Estimated delivery date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 209: LMP must be selected when LMP method chosen
            # This is a checkbox field
            
            # Rule 210: Clinical exam must be selected when clinical method chosen
            # Checkbox field
            
            # Rule 211: Ultrasound must be selected when ultrasound method chosen
            # Checkbox field
            
            # Rule 212: LMP date type must be valid
            self.add_rule(
                field='date_lmp_type',
                validation_func=lambda x: x in ['CH00984', 'CH00985'] if x and str(x).strip() else True,
                error_msg='Invalid LMP date type',
                suggestion='Select Exact or Approximate',
                severity='Warning'
            )
            
            # Rule 213: LMP date cannot be future
            self.add_rule(
                field='date_lmp',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='LMP date cannot be in the future',
                suggestion='Correct the LMP date',
                severity='Critical'
            )
            
            # Rule 214: LMP date must be after 2019
            self.add_rule(
                field='date_lmp',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='LMP date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 215: Other estimation method specification required
            self.add_rule(
                field='est_delivery_method_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other estimation method specification required',
                suggestion='Specify the estimation method',
                severity='Critical'
            )
            
            # Rule 216: Other estimation method length
            self.add_rule(
                field='est_delivery_method_other',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Estimation method exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 217: ANC care must be valid
            self.add_rule(
                field='anc_care_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for ANC care',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 218: First ANC date cannot be future
            self.add_rule(
                field='date_anc_first_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='First ANC date cannot be in the future',
                suggestion='Correct the ANC visit date',
                severity='Critical'
            )
            
            # Rule 219: First ANC date must be after 2019
            self.add_rule(
                field='date_anc_first_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='First ANC date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 220: Hours on feet must be between 0-24
            self.add_rule(
                field='hours_on_feet',
                validation_func=lambda x: 0 <= int(x) <= 24 if x and str(x).strip() else True,
                error_msg='Hours on feet must be between 0 and 24',
                suggestion='Enter a value between 0 and 24 hours',
                severity='Warning'
            )
            
            # Rule 221: Hours on feet must be integer
            self.add_rule(
                field='hours_on_feet',
                validation_func=lambda x: str(x).isdigit() if x and str(x).strip() else True,
                error_msg='Hours on feet must be a whole number',
                suggestion='Enter a whole number of hours',
                severity='Warning'
            )
            
            # Rule 222: Ultrasound date type must be valid
            self.add_rule(
                field='date_us_pre_type',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid ultrasound date type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 223: Ultrasound date cannot be future
            self.add_rule(
                field='date_us_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Ultrasound date cannot be in the future',
                suggestion='Correct the ultrasound date',
                severity='Critical'
            )
            
            # Rule 224: Ultrasound date must be after 2019
            self.add_rule(
                field='date_us_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Ultrasound date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 225: Gestational age weeks must be between 1-52
            self.add_rule(
                field='gestage_wk_pre',
                validation_func=lambda x: 1 <= int(x) <= 52 if x and str(x).strip() else True,
                error_msg='Gestational age weeks must be between 1 and 52',
                suggestion='Enter a valid gestational age in weeks',
                severity='Critical'
            )
            
            # Rule 226: Gestational age weeks must be integer
            self.add_rule(
                field='gestage_wk_pre',
                validation_func=lambda x: str(x).isdigit() if x and str(x).strip() else True,
                error_msg='Gestational age weeks must be a whole number',
                suggestion='Enter a whole number of weeks',
                severity='Critical'
            )
            
            # Rule 227: Gestational age days must be between 0-6
            self.add_rule(
                field='gestage_day_pre',
                validation_func=lambda x: 0 <= int(x) <= 6 if x and str(x).strip() else True,
                error_msg='Gestational age days must be between 0 and 6',
                suggestion='Enter a value between 0 and 6 days',
                severity='Critical'
            )
            
            # Rule 228: Gestational age days must be integer
            self.add_rule(
                field='gestage_day_pre',
                validation_func=lambda x: str(x).isdigit() if x and str(x).strip() else True,
                error_msg='Gestational age days must be a whole number',
                suggestion='Enter a whole number of days',
                severity='Critical'
            )
            
            # Rule 229: Height known must be valid
            self.add_rule(
                field='height_known_mom',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for height known',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 230: Height value must be positive
            self.add_rule(
                field='height_value_mom',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
                error_msg='Height must be a positive number',
                suggestion='Enter a valid height measurement',
                severity='Warning'
            )
            
            # Rule 231: Height value must be reasonable (100-250 cm)
            self.add_rule(
                field='height_value_mom',
                validation_func=lambda x: 100 <= float(x) <= 250 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Height value seems unreasonable',
                suggestion='Verify height is between 100-250 cm or 39-98 inches',
                severity='Warning'
            )
            
            # Rule 232: Height unit must be valid
            self.add_rule(
                field='height_unit_mom',
                validation_func=lambda x: x in ['CH00113', 'CH00112'] if x and str(x).strip() else True,
                error_msg='Invalid height unit',
                suggestion='Select centimeters (cm) or inches (in)',
                severity='Warning'
            )
            
            # Rule 233: Height method must be valid
            self.add_rule(
                field='height_method_mom',
                validation_func=lambda x: x in ['CH02372', 'CH02373', 'CH02374'] if x and str(x).strip() else True,
                error_msg='Invalid height determination method',
                suggestion='Select measured, from documents, or self-report',
                severity='Warning'
            )
            
            # Rule 234: Weight before pregnancy known must be valid
            self.add_rule(
                field='weight_b4_known_mom_pre',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for weight before pregnancy',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 235: Weight before pregnancy must be positive
            self.add_rule(
                field='weight_b4_value_mom_pre',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
                error_msg='Weight before pregnancy must be a positive number',
                suggestion='Enter a valid weight in kg',
                severity='Warning'
            )
            
            # Rule 236: Weight before pregnancy must be reasonable (30-150 kg)
            self.add_rule(
                field='weight_b4_value_mom_pre',
                validation_func=lambda x: 30 <= float(x) <= 150 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Weight before pregnancy seems unreasonable',
                suggestion='Verify weight is between 30-150 kg',
                severity='Warning'
            )
            
            # Rule 237: Weight during pregnancy known must be valid
            self.add_rule(
                field='weight_known_mom_pre',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for weight during pregnancy',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 238: Weight during pregnancy must be positive
            self.add_rule(
                field='weight_value_mom_pre',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
                error_msg='Weight during pregnancy must be a positive number',
                suggestion='Enter a valid weight in kg',
                severity='Warning'
            )
            
            # Rule 239: Weight during pregnancy must be reasonable (30-200 kg)
            self.add_rule(
                field='weight_value_mom_pre',
                validation_func=lambda x: 30 <= float(x) <= 200 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Weight during pregnancy seems unreasonable',
                suggestion='Verify weight is between 30-200 kg',
                severity='Warning'
            )
            
            # Rule 240: Weight method must be valid
            self.add_rule(
                field='weight_method_mom_pre',
                validation_func=lambda x: x in ['CH02372', 'CH02373', 'CH02374'] if x and str(x).strip() else True,
                error_msg='Invalid weight determination method',
                suggestion='Select measured, from documents, or self-report',
                severity='Warning'
            )
            
            # Rule 241: Weight date type must be valid
            self.add_rule(
                field='date_weight_mom_type_pre',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid weight date type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 242: Weight date cannot be future
            self.add_rule(
                field='date_weight_mom_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Weight measurement date cannot be in the future',
                suggestion='Correct the weight measurement date',
                severity='Critical'
            )
            
            # Rule 243: Weight date must be after 2019
            self.add_rule(
                field='date_weight_mom_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Weight measurement date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 244: MUAC known must be valid
            self.add_rule(
                field='muac_mom_known_pre',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for MUAC known',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 245: MUAC value must be positive
            self.add_rule(
                field='muac_mom_value_pre',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
                error_msg='MUAC must be a positive number',
                suggestion='Enter a valid MUAC measurement in cm',
                severity='Warning'
            )
            
            # Rule 246: MUAC value must be reasonable (10-50 cm)
            self.add_rule(
                field='muac_mom_value_pre',
                validation_func=lambda x: 10 <= float(x) <= 50 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='MUAC value seems unreasonable',
                suggestion='Verify MUAC is between 10-50 cm',
                severity='Warning'
            )
            
            # Rule 247: MUAC method must be valid
            self.add_rule(
                field='muac_mom_method_pre',
                validation_func=lambda x: x in ['CH02372', 'CH02373'] if x and str(x).strip() else True,
                error_msg='Invalid MUAC determination method',
                suggestion='Select measured or from documents',
                severity='Warning'
            )
            
            # Rule 248: Anemia test must be valid
            self.add_rule(
                field='anemia_test_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia test',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 249: Anemia diagnosis must be valid
            self.add_rule(
                field='anemia_diag_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia diagnosis',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 250: Hemoglobin known must be valid
            self.add_rule(
                field='hemog_known_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for hemoglobin known',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 251: Hemoglobin value must be positive
            self.add_rule(
                field='hemog_value_pre',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
                error_msg='Hemoglobin must be a positive number',
                suggestion='Enter a valid hemoglobin level',
                severity='Warning'
            )
            
            # Rule 252: Hemoglobin value must be reasonable (2-20 g/dL)
            self.add_rule(
                field='hemog_value_pre',
                validation_func=lambda x: 2 <= float(x) <= 20 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Hemoglobin value seems unreasonable',
                suggestion='Verify hemoglobin is between 2-20 g/dL',
                severity='Warning'
            )
            
            # Rule 253: Hemoglobin unit must be valid
            self.add_rule(
                field='hemog_unit_pre',
                validation_func=lambda x: x in ['CH02333', 'CH02334'] if x and str(x).strip() else True,
                error_msg='Invalid hemoglobin unit',
                suggestion='Select g/dL or mmol/L',
                severity='Warning'
            )
            
            # Rule 254: Hemoglobin date cannot be future
            self.add_rule(
                field='date_hemog_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Hemoglobin measurement date cannot be in the future',
                suggestion='Correct the hemoglobin measurement date',
                severity='Critical'
            )
            
            # Rule 255: Hemoglobin date must be after 2019
            self.add_rule(
                field='date_hemog_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Hemoglobin measurement date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 256: Heavy bleeding during pregnancy must be valid
            self.add_rule(
                field='hp_vbleed_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for heavy vaginal bleeding during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 257: UTI during pregnancy must be valid
            self.add_rule(
                field='hp_uti_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for UTI during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 258: Hypertension during pregnancy must be valid
            self.add_rule(
                field='hp_highbp_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for hypertension during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 259: Preeclampsia during pregnancy must be valid
            self.add_rule(
                field='hp_preclamp_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for preeclampsia during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 260: Eclampsia during pregnancy must be valid
            self.add_rule(
                field='hp_eclamp_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for eclampsia during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 261: Other seizures during pregnancy must be valid
            self.add_rule(
                field='hp_oth_seiz_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other seizures during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 262: Unplanned hospitalization during pregnancy must be valid
            self.add_rule(
                field='hp_uphosp_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for unplanned hospitalization during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 263: Hospitalization reason during pregnancy required when Yes
            self.add_rule(
                field='hp_uphosp_reason_dur',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Hospitalization reason during pregnancy required when "Yes" selected',
                suggestion='Specify the reason for hospitalization',
                severity='Critical'
            )
            
            # Rule 264: Hospitalization reason length
            self.add_rule(
                field='hp_uphosp_reason_dur',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Hospitalization reason exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 265: Trauma during pregnancy must be valid
            self.add_rule(
                field='hp_trauma_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for trauma during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 266: Trauma specification during pregnancy required when Yes
            self.add_rule(
                field='hp_trauma_specify_dur',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Trauma specification during pregnancy required when "Yes" selected',
                suggestion='Specify the accident/assault/trauma',
                severity='Critical'
            )
            
            # Rule 267: Trauma specification length
            self.add_rule(
                field='hp_trauma_specify_dur',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Trauma specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 268: Malaria during pregnancy must be valid
            self.add_rule(
                field='hp_malaria_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for malaria during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 269: Diabetes during pregnancy must be valid
            self.add_rule(
                field='hp_diabetes_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for diabetes during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 270: Anemia during pregnancy must be valid
            self.add_rule(
                field='hp_anemia_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 271: HIV during pregnancy must be valid
            self.add_rule(
                field='hp_hiv_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for HIV during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 272: Mental health during pregnancy must be valid
            self.add_rule(
                field='hp_mental_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for mental health during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 273: COVID exposure during pregnancy must be valid
            self.add_rule(
                field='hp_covidex_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 274: COVID diagnosis during pregnancy must be valid
            self.add_rule(
                field='hp_covid_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 275: Other health problem during pregnancy must be valid
            self.add_rule(
                field='hp_other_dur',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem during pregnancy',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 276: Other health problem specification required when Yes
            self.add_rule(
                field='hp_other_specify_dur',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other health problem specification required when "Yes" selected',
                suggestion='Specify the other health problem',
                severity='Critical'
            )
            
            # Rule 277: Other health problem specification length
            self.add_rule(
                field='hp_other_specify_dur',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Health problem specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 278: Maternal health card source selected
            # Checkbox field
            
            # Rule 279: Antenatal care records source selected
            # Checkbox field
            
            # Rule 280: Delivery records source selected
            # Checkbox field
            
            # Rule 281: Interview with mother source selected
            # Checkbox field
            
            # Rule 282: Other form source specification required when selected
            self.add_rule(
                field='form_source_other_pre',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other form source specification required',
                suggestion='Specify the other data source',
                severity='Critical'
            )
            
            # Rule 283: Other form source length
            self.add_rule(
                field='form_source_other_pre',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Form source specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 284: Prenatal form completion date cannot be future
            self.add_rule(
                field='date_form_complete_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Prenatal form completion date cannot be in the future',
                suggestion='Correct the form completion date',
                severity='Critical'
            )
            
            # Rule 285: Prenatal form completion date must be after 2019
            self.add_rule(
                field='date_form_complete_pre',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Prenatal form completion date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 286: Maternal health card source selected for prenatal
            # This is a helper method to check checkbox fields
            
            # Rule 287: Antenatal care records source selected
            # Helper method
            
            # Rule 288: Delivery records source selected
            # Helper method
            
            # Rule 289: Interview with mother source selected
            # Helper method
            
            # Rule 290: Form completion date cannot be before delivery
            # This requires cross-field validation
            
            # Rule 291: Weight measurement date cannot be after delivery
            # Cross-field validation
            
            # Rule 292: Hemoglobin measurement date cannot be after delivery
            # Cross-field validation
            
            # Rule 293: Ultrasound date cannot be after delivery
            # Cross-field validation
            
            # Rule 294: ANC dates must be before delivery
            # Cross-field validation
            
            # Rule 295: Estimated delivery date should be after LMP
            # Cross-field validation
            
            # Rule 296: Gestational age should be consistent with dates
            # Cross-field validation
            
            # Rule 297: Number of miscarriages + stillbirths + live births should equal total pregnancies
            # Cross-field validation
            
            # Rule 298: Premature + full-term stillbirths should equal total stillbirths
            # Cross-field validation
            
            # Rule 299: Premature + full-term live births should equal total live births
            # Cross-field validation
            
            # Rule 300: Neonatal deaths cannot exceed live births
                    # =============================================================================
    # BATCH 4: DAY 01 MATERNAL FORM - DELIVERY INFORMATION & TREATMENTS (Rules 301-400)
    # =============================================================================

        # Rule 301: Day 01 context with prenatal must be valid
            self.add_rule(
                field='context_md01_to_pre',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for Day 01 form completion timing with prenatal',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 302: GPS Latitude format must be valid
            self.add_rule(
                field='gps_atday01',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS latitude format',
                suggestion='Enter a valid latitude coordinate (e.g., 9.3122)',
                severity='Warning'
            )
            
            # Rule 303: GPS Latitude range must be valid for Ethiopia
            self.add_rule(
                field='gps_atday01',
                validation_func=lambda x: 3.0 <= float(x) <= 15.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS latitude outside expected range for Ethiopia',
                suggestion='Latitude should be between 3°N and 15°N',
                severity='Warning'
            )
            
            # Rule 304: GPS Longitude format must be valid
            self.add_rule(
                field='gpslong_atday01m',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS longitude format',
                suggestion='Enter a valid longitude coordinate (e.g., 42.1234)',
                severity='Warning'
            )
            
            # Rule 305: GPS Longitude range must be valid for Ethiopia
            self.add_rule(
                field='gpslong_atday01m',
                validation_func=lambda x: 33.0 <= float(x) <= 48.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS longitude outside expected range for Ethiopia',
                suggestion='Longitude should be between 33°E and 48°E',
                severity='Warning'
            )
            
            # Rule 306: Day 01 interviewer ID is required
            self.add_rule(
                field='interviewer_id_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewer ID is required for Day 01 form',
                suggestion='Enter the interviewer ID',
                severity='Critical'
            )
            
            # Rule 307: Day 01 interviewee is mother must be valid
            self.add_rule(
                field='interview_mom_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for interviewee being the mother',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 308: Day 01 interviewee name required when not mother
            self.add_rule(
                field='interviewee_name_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewee name is required when interviewee is not the mother',
                suggestion='Enter the name of the person being interviewed',
                severity='Critical'
            )
            
            # Rule 309: Day 01 husband relationship selected
            # Checkbox field
            
            # Rule 310: Day 01 child relationship selected
            # Checkbox field
            
            # Rule 311: Day 01 mother relationship selected
            # Checkbox field
            
            # Rule 312: Day 01 father relationship selected
            # Checkbox field
            
            # Rule 313: Day 01 mother-in-law relationship selected
            # Checkbox field
            
            # Rule 314: Day 01 father-in-law relationship selected
            # Checkbox field
            
            # Rule 315: Day 01 aunt/uncle relationship selected
            # Checkbox field
            
            # Rule 316: Day 01 cousin relationship selected
            # Checkbox field
            
            # Rule 317: Day 01 other relationship specification required when selected
            self.add_rule(
                field='intview_relation_oth_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Relationship specification required when "Other" is selected',
                suggestion='Specify the relationship to the mother',
                severity='Critical'
            )
            
            # Rule 318: Day 01 other relationship length
            self.add_rule(
                field='intview_relation_oth_md01',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Relationship specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 319: Day 01 address change must be valid
            self.add_rule(
                field='address_chg_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for address change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 320: Day 01 updated address required when changed
            self.add_rule(
                field='address_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Updated address is required when address changed',
                suggestion='Enter the new address',
                severity='Critical'
            )
            
            # Rule 321: Day 01 phone change must be valid
            self.add_rule(
                field='phone_chg_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for phone change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 322: Day 01 updated phone number length
            self.add_rule(
                field='phone_md01',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Updated phone number exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 323: Day 01 updated phone number format
            self.add_rule(
                field='phone_md01',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Updated phone number must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 324: Delivery date type must be valid
            self.add_rule(
                field='date_delivery_type',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid delivery date type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 325: Delivery date cannot be future
            self.add_rule(
                field='date_delivery',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Delivery date cannot be in the future',
                suggestion='Correct the delivery date',
                severity='Critical'
            )
            
            # Rule 326: Delivery date must be after 2019
            self.add_rule(
                field='date_delivery',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Delivery date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 327: Delivery date should be after LMP
            # Cross-field validation
            
            # Rule 328: Specialist Doctor/Obstetrician selected
            # Checkbox field
            
            # Rule 329: Non-Obstetrician Physician selected
            # Checkbox field
            
            # Rule 330: Nurse selected
            # Checkbox field
            
            # Rule 331: Midwife selected
            # Checkbox field
            
            # Rule 332: Assistant Medical Officer selected
            # Checkbox field
            
            # Rule 333: Health Provider Unknown Cadre selected
            # Checkbox field
            
            # Rule 334: Family Member selected
            # Checkbox field
            
            # Rule 335: Traditional birth attendant selected
            # Checkbox field
            
            # Rule 336: Unattended/Self Delivery selected
            # Checkbox field
            
            # Rule 337: Other delivery person specification required when selected
            self.add_rule(
                field='delivery_by_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other delivery person specification required',
                suggestion='Specify who conducted the delivery',
                severity='Critical'
            )
            
            # Rule 338: Other delivery person length
            self.add_rule(
                field='delivery_by_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Delivery person specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 339: Delivery location must be valid
            self.add_rule(
                field='deliv_location',
                validation_func=lambda x: x in ['CH00012', 'CH00013', 'CH00014', 'CH00015', 'CH00016',
                                            'CH01839', 'CH01840', 'CH01841', 'CH00017', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery location',
                suggestion='Select a valid location from the list',
                severity='Critical'
            )
            
            # Rule 340: Delivery facility must be valid when facility selected
            self.add_rule(
                field='deliv_facility',
                validation_func=lambda x: x in ['CH02648', 'CH02654', 'CH02652', 'CH02647', 'CH02646', 'CH01998',
                                            'CH02730', 'CH02651', 'CH02649', 'CH02650', 'CH02635', 'CH02637',
                                            'CH02634', 'CH02643', 'CH02642', 'CH02639', 'CH02640', 'CH02002',
                                            'CH02633', 'CH02638', 'CH02644', 'CH02636', 'CH02641', 'CH01995',
                                            'CH01996', 'CH01997', 'CH02007', 'CH02008', 'CH02009', 'CH02645',
                                            'CH01857', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid delivery facility',
                suggestion='Select a valid health facility from the list',
                severity='Critical'
            )
            
            # Rule 341: Other delivery facility specification required when "Other" selected
            self.add_rule(
                field='deliv_facility_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other delivery facility specification required',
                suggestion='Specify the delivery facility',
                severity='Critical'
            )
            
            # Rule 342: Other delivery facility length
            self.add_rule(
                field='deliv_facility_other',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Delivery facility specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 343: Delivery village catchment must be valid
            self.add_rule(
                field='deliv_vill_md01',
                validation_func=lambda x: x in ['1', '2', '3'] if x and str(x).strip() else True,
                error_msg='Invalid delivery catchment ID',
                suggestion='Select 1=Harar, 2=Haramaya, 3=Kersa',
                severity='Critical'
            )
            
            # Rule 344: Delivery sub-district for Haramaya must be valid
            self.add_rule(
                field='deliv_vill_md01_haramaya',
                validation_func=lambda x: x in ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery sub-district for Haramaya',
                suggestion='Select from F01-F12',
                severity='Critical'
            )
            
            # Rule 345: Delivery F01 village must be valid
            self.add_rule(
                field='villcode_har_f01_md01',
                validation_func=lambda x: x in ['53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64',
                                            '65', '66', '67', '68', '69', '70', '71', '72', '73', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F01 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 346: Delivery F02 village must be valid
            self.add_rule(
                field='villcode_har_f02_md01',
                validation_func=lambda x: x in ['74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85',
                                            '86', '87', '88', '89', '90', '91', '92', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F02 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 347: Delivery F03 village must be valid
            self.add_rule(
                field='villcode_har_f03_md01',
                validation_func=lambda x: x in ['93', '94', '95', '96', '97', '98', '99', '100', '101', '102', '103', '104',
                                            '105', '106', '107', '108', '109', '110', '111', '112', '113', '114', '115', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F03 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 348: Delivery F04 village must be valid
            self.add_rule(
                field='villcode_har_f04_md01',
                validation_func=lambda x: x in ['116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '127', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F04 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 349: Delivery F05 village must be valid
            self.add_rule(
                field='villcode_har_f05_md01',
                validation_func=lambda x: x in ['128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138',
                                            '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F05 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 350: Delivery F06 village must be valid
            self.add_rule(
                field='villcode_har_f06_md01',
                validation_func=lambda x: x in ['150', '151', '152', '153', '154', '155', '156', '157', '158', '159', '160',
                                            '161', '162', '163', '164', '165', '166', '167', '168', '169', '170', '171',
                                            '172', '173', '174', '175', '176', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F06 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 351: Delivery F07 village must be valid
            self.add_rule(
                field='villcode_har_f07_md01',
                validation_func=lambda x: x in ['177', '178', '179', '180', '181', '182', '183', '184', '185', '186', '187',
                                            '188', '189', '190', '191', '192', '193', '194', '195', '196', '197', '198',
                                            '199', '200', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F07 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 352: Delivery F08 village must be valid
            self.add_rule(
                field='villcode_har_f08_md01',
                validation_func=lambda x: x in ['201', '202', '203', '204', '205', '206', '207', '208', '209', '210', '211',
                                            '212', '213', '214', '215', '216', '217', '218', '219', '220', '221', '222',
                                            '223', '224', '225', '226', '227', '228', '229', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F08 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 353: Delivery F09 village must be valid
            self.add_rule(
                field='villcode_har_f09_md01',
                validation_func=lambda x: x in ['230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240',
                                            '241', '242', '243', '244', '245', '246', '247', '248', '249', '250', '251',
                                            '252', '253', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F09 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 354: Delivery F10 village must be valid
            self.add_rule(
                field='villcode_har_f10_md01',
                validation_func=lambda x: x in ['254', '255', '256', '257', '258', '259', '260', '261', '262', '263', '264',
                                            '265', '266', '267', '268', '269', '270', '271', '272', '273', '274', '275',
                                            '276', '277', '278', '279', '280', '281', '282', '283', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F10 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 355: Delivery F11 village must be valid
            self.add_rule(
                field='villcode_har_f11_md01',
                validation_func=lambda x: x in ['284', '285', '286', '287', '288', '289', '290', '291', '292', '293', '294',
                                            '295', '296', '297', '298', '299', '300', '301', '302', '303', '304', '305',
                                            '306', '307', '308', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery F11 village code',
                suggestion='Select a valid village code or 999 for Other',
                severity='Critical'
            )
            
            # Rule 356: Delivery F12 village must be valid
            self.add_rule(
                field='villcode_har_f12_md01',
                validation_func=lambda x: x in ['309', '310', '311', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery F12 village code',
                suggestion='Select 309, 310, 311, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 357: Delivery sub-district for Harar must be valid
            self.add_rule(
                field='subdis_rar_md01',
                validation_func=lambda x: x in ['17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery sub-district for Harar',
                suggestion='Select from H01-H18',
                severity='Critical'
            )
            
            # Rule 358: Delivery H01 village must be valid
            self.add_rule(
                field='villcode_rar_h01_md01',
                validation_func=lambda x: x in ['312', '339', '340', '341', '342', '343', '344', '345', '346', '347', '348',
                                            '349', '350', '351', '352', '353', '354', '355', '356', '357', '358', '359',
                                            '360', '361', '362', '363', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H01 village code',
                suggestion='Select A01-A26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 359: Delivery H02 village must be valid
            self.add_rule(
                field='villcode_rar_h02_md01',
                validation_func=lambda x: x in ['364', '365', '366', '367', '368', '369', '370', '371', '372', '373', '374',
                                            '375', '376', '377', '378', '379', '380', '381', '382', '383', '384', '385',
                                            '386', '387', '388', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H02 village code',
                suggestion='Select M01-M25 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 360: Delivery H04 village must be valid
            self.add_rule(
                field='villcode_rar_h04_md01',
                validation_func=lambda x: x in ['389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399',
                                            '400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H04 village code',
                suggestion='Select B01-B22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 361: Delivery H05 village must be valid
            self.add_rule(
                field='villcode_rar_h05_md01',
                validation_func=lambda x: x in ['411', '412', '413', '414', '415', '416', '417', '418', '419', '420', '421',
                                            '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432',
                                            '433', '434', '435', '436', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H05 village code',
                suggestion='Select D01-D26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 362: Delivery H08 village must be valid
            self.add_rule(
                field='villcode_rar_h08_md01',
                validation_func=lambda x: x in ['437', '438', '439', '440', '441', '442', '443', '444', '445', '446', '447',
                                            '448', '449', '450', '451', '452', '453', '454', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H08 village code',
                suggestion='Select S01-S18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 363: Delivery H10 village must be valid
            self.add_rule(
                field='villcode_rar_h10_md01',
                validation_func=lambda x: x in ['455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465',
                                            '466', '467', '468', '469', '470', '471', '472', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H10 village code',
                suggestion='Select W01-W18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 364: Delivery H12 village must be valid
            self.add_rule(
                field='villcode_rar_h12_md01',
                validation_func=lambda x: x in ['473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483',
                                            '484', '485', '486', '487', '488', '489', '490', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H12 village code',
                suggestion='Select C01-C18 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 365: Delivery H13 village must be valid
            self.add_rule(
                field='villcode_rar_h13_md01',
                validation_func=lambda x: x in ['491', '492', '493', '494', '495', '496', '497', '498', '499', '500', '501',
                                            '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '512', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H13 village code',
                suggestion='Select R01-R22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 366: Delivery H15 village must be valid
            self.add_rule(
                field='villcode_rar_h15_md01',
                validation_func=lambda x: x in ['513', '514', '515', '516', '517', '518', '519', '520', '521', '522', '523',
                                            '524', '525', '526', '527', '528', '529', '530', '531', '532', '533', '534',
                                            '535', '536', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H15 village code',
                suggestion='Select J01-J24 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 367: Delivery H16 village must be valid
            self.add_rule(
                field='villcode_rar_h16_md01',
                validation_func=lambda x: x in ['537', '538', '539', '540', '541', '542', '543', '544', '545', '546', '547',
                                            '548', '549', '550', '551', '552', '553', '554', '555', '556', '557', '558', '559', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H16 village code',
                suggestion='Select N01-N23 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 368: Delivery H17 village must be valid
            self.add_rule(
                field='villcode_rar_h17_md01',
                validation_func=lambda x: x in ['560', '561', '562', '563', '564', '565', '566', '567', '568', '569', '570',
                                            '571', '572', '573', '574', '575', '576', '577', '578', '579', '580', '581',
                                            '582', '583', '584', '585', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H17 village code',
                suggestion='Select I01-I26 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 369: Delivery H18 village must be valid
            self.add_rule(
                field='villcode_rar_h18_md01',
                validation_func=lambda x: x in ['586', '587', '588', '589', '590', '591', '592', '593', '594', '595', '596',
                                            '597', '598', '599', '600', '601', '602', '603', '604', '605', '606', '607', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery H18 village code',
                suggestion='Select E01-E22 or 999 for Other',
                severity='Critical'
            )
            
            # Rule 370: Delivery sub-district for Kersa must be valid
            self.add_rule(
                field='subdis_ker_md01',
                validation_func=lambda x: x in ['29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', 
                                            '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery sub-district for Kersa',
                suggestion='Select from K01-K24',
                severity='Critical'
            )
            
            # Rule 371: Delivery K01 village must be valid
            self.add_rule(
                field='villcode_ker_k01_md01',
                validation_func=lambda x: x in ['608', '609', '610', '611', '612', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K01 village code',
                suggestion='Select KE0, KEA, KEB, KEC, KED, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 372: Delivery K02 village must be valid
            self.add_rule(
                field='villcode_ker_k02_md01',
                validation_func=lambda x: x in ['613', '614', '615', '616', '617', '618', '619', '620', '621', '622', '623',
                                            '624', '625', '626', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K02 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 373: Delivery K03 village must be valid
            self.add_rule(
                field='villcode_ker_k03_md01',
                validation_func=lambda x: x in ['627', '628', '629', '630', '631', '632', '633', '634', '635', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K03 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 374: Delivery K04 village must be valid
            self.add_rule(
                field='villcode_ker_k04_md01',
                validation_func=lambda x: x in ['636', '637', '638', '639', '640', '641', '642', '643', '644', '645', '646', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K04 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 375: Delivery K05 village must be valid
            self.add_rule(
                field='villcode_ker_k05_md01',
                validation_func=lambda x: x in ['647', '648', '649', '650', '651', '652', '653', '654', '655', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K05 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 376: Delivery K06 village must be valid
            self.add_rule(
                field='villcode_ker_k06_md01',
                validation_func=lambda x: x in ['656', '657', '658', '659', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K06 village code',
                suggestion='Select GEB, GEC, GED, GEE, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 377: Delivery K07 village must be valid
            self.add_rule(
                field='villcode_ker_k07_md01',
                validation_func=lambda x: x in ['660', '661', '662', '663', '664', '665', '666', '667', '668', '669', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K07 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 378: Delivery K08 village must be valid
            self.add_rule(
                field='villcode_ker_k08_md01',
                validation_func=lambda x: x in ['670', '671', '672', '673', '674', '675', '676', '677', '678', '679', '680', '681', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K08 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 379: Delivery K09 village must be valid
            self.add_rule(
                field='villcode_ker_k09_md01',
                validation_func=lambda x: x in ['682', '683', '684', '685', '686', '687', '688', '689', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K09 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 380: Delivery K10 village must be valid
            self.add_rule(
                field='villcode_ker_k10_md01',
                validation_func=lambda x: x in ['690', '691', '692', '693', '694', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K10 village code',
                suggestion='Select ABE, BEB, BUR, KOT, MEA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 381: Delivery K11 village must be valid
            self.add_rule(
                field='villcode_ker_k11_md01',
                validation_func=lambda x: x in ['695', '696', '697', '698', '699', '700', '701', '702', '703', '704', '705',
                                            '706', '707', '708', '709', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K11 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 382: Delivery K12 village must be valid
            self.add_rule(
                field='villcode_ker_k12_md01',
                validation_func=lambda x: x in ['710', '711', '712', '713', '714', '715', '716', '717', '718', '719', '720',
                                            '721', '722', '723', '724', '725', '726', '727', '728', '729', '730', '731',
                                            '732', '733', '734', '735', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K12 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 383: Delivery K13 village must be valid
            self.add_rule(
                field='villcode_ker_k13_md01',
                validation_func=lambda x: x in ['736', '737', '738', '739', '740', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K13 village code',
                suggestion='Select KE1, KE2, KE3, KE4, KE5, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 384: Delivery K14 village must be valid
            self.add_rule(
                field='villcode_ker_k14_md01',
                validation_func=lambda x: x in ['741', '742', '743', '744', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K14 village code',
                suggestion='Select ALI, BEY, GOC, TUA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 385: Delivery K15 village must be valid
            self.add_rule(
                field='villcode_ker_k15_md01',
                validation_func=lambda x: x in ['745', '746', '747', '748', '749', '750', '751', '752', '753', '754', '755', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K15 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 386: Delivery K16 village must be valid
            self.add_rule(
                field='villcode_ker_k16_md01',
                validation_func=lambda x: x in ['756', '757', '758', '759', '760', '761', '762', '763', '764', '765', '766',
                                            '767', '768', '769', '770', '771', '772', '773', '774', '775', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K16 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 387: Delivery K17 village must be valid
            self.add_rule(
                field='villcode_ker_k17_md01',
                validation_func=lambda x: x in ['776', '777', '778', '779', '780', '781', '782', '783', '784', '785', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K17 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 388: Delivery K18 village must be valid
            self.add_rule(
                field='villcode_ker_k18_md01',
                validation_func=lambda x: x in ['786', '787', '788', '789', '790', '791', '792', '793', '794', '795', '796',
                                            '797', '798', '799', '800', '801', '802', '803', '804', '805', '806', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K18 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 389: Delivery K19 village must be valid
            self.add_rule(
                field='villcode_ker_k19_md01',
                validation_func=lambda x: x in ['807', '808', '809', '810', '811', '812', '813', '814', '815', '816', '817', '818', '819', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K19 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 390: Delivery K20 village must be valid
            self.add_rule(
                field='villcode_ker_k20_md01',
                validation_func=lambda x: x in ['820', '821', '822', '823', '824', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K20 village code',
                suggestion='Select ABB, DEA, HAL, KOA, SOA, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 391: Delivery K21 village must be valid
            self.add_rule(
                field='villcode_ker_k21_md01',
                validation_func=lambda x: x in ['825', '826', '827', '828', '829', '830', '831', '832', '833', '834', '835', '836', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K21 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 392: Delivery K22 village must be valid
            self.add_rule(
                field='villcode_ker_k22_md01',
                validation_func=lambda x: x in ['837', '838', '839', '840', '841', '842', '843', '844', '845', '846', '847',
                                            '848', '849', '850', '851', '852', '853', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K22 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 393: Delivery K23 village must be valid
            self.add_rule(
                field='villcode_ker_k23_md01',
                validation_func=lambda x: x in ['854', '855', '856', '857', '858', '999'] if x and str(x).strip() else True,
                error_msg='Invalid delivery K23 village code',
                suggestion='Select ARB, GEK, SEK, WAD, WOR, or 999 for Other',
                severity='Critical'
            )
            
            # Rule 394: Delivery K24 village must be valid
            self.add_rule(
                field='villcode_ker_k24_md01',
                validation_func=lambda x: x in ['859', '860', '861', '862', '863', '864', '865', '866', '867', '999'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery K24 village code',
                suggestion='Select from list or 999 for Other',
                severity='Critical'
            )
            
            # Rule 395: Other delivery village specification required when 999 selected
            self.add_rule(
                field='vill_specifyothermd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other delivery village specification required when "Other" is selected',
                suggestion='Specify the village name',
                severity='Critical'
            )
            
            # Rule 396: Other delivery location specification required
            self.add_rule(
                field='deliv_location_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other delivery location specification required',
                suggestion='Specify the delivery location',
                severity='Critical'
            )
            
            # Rule 397: Other delivery location length
            self.add_rule(
                field='deliv_location_other',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Delivery location specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 398: Antibiotics during delivery must be valid
            self.add_rule(
                field='tr_antibiot_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for antibiotics during delivery',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 399: Corticosteroids during delivery must be valid
            self.add_rule(
                field='tr_cortico_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for corticosteroids during delivery',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 400: Oxytocin or Misoprostol during delivery must be valid
            self.add_rule(
                field='tr_oxymiso_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for oxytocin/misoprostol during delivery',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
                )
                                # =============================================================================
        # BATCH 6: DAY 01 MATERNAL FORM - HEALTH PROBLEMS CONTINUED & ANC (Rules 501-600)
        # =============================================================================

            # Rule 501: Trauma hospitalization days must be positive
            self.add_rule(
                field='hp_trauma_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 502: HIV after prenatal must be valid
            self.add_rule(
                field='hp_hiv_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for HIV',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 503: HIV hospitalization must be valid
            self.add_rule(
                field='hp_hiv_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for HIV hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 504: HIV hospitalization days must be positive
            self.add_rule(
                field='hp_hiv_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 505: Mental health problem after prenatal must be valid
            self.add_rule(
                field='hp_mental_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for mental health problem',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 506: Mental health hospitalization must be valid
            self.add_rule(
                field='hp_mental_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for mental health hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 507: Mental health hospitalization days must be positive
            self.add_rule(
                field='hp_mental_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 508: COVID exposure after prenatal must be valid
            self.add_rule(
                field='hp_covidex_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 509: COVID exposure hospitalization must be valid
            self.add_rule(
                field='hp_covidex_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 510: COVID exposure hospitalization days must be positive
            self.add_rule(
                field='hp_covidex_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 511: COVID diagnosis after prenatal must be valid
            self.add_rule(
                field='hp_covid_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 512: COVID diagnosis hospitalization must be valid
            self.add_rule(
                field='hp_covid_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 513: COVID diagnosis hospitalization days must be positive
            self.add_rule(
                field='hp_covid_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 514: Abruption placentae must be valid
            self.add_rule(
                field='hp_placabrup_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for abruption placentae',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 515: Abruption percentage must be between 0-100
            self.add_rule(
                field='hp_placabrupperc_md01',
                validation_func=lambda x: 0 <= float(x) <= 100 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Abruption percentage must be between 0 and 100',
                suggestion='Enter a percentage between 0 and 100',
                severity='Warning'
            )
            
            # Rule 516: Abruption hospitalization must be valid
            self.add_rule(
                field='hp_placabrup_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for abruption hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 517: Abruption hospitalization days must be positive
            self.add_rule(
                field='hp_placabrup_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 518: Other health problem after prenatal must be valid
            self.add_rule(
                field='hp_other_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 519: Other health problem specification required when Yes selected
            self.add_rule(
                field='hp_other_specify_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other health problem specification required when "Yes" selected',
                suggestion='Specify the other health problem',
                severity='Critical'
            )
            
            # Rule 520: Other health problem specification length
            self.add_rule(
                field='hp_other_specify_md01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Health problem specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 521: Other health problem hospitalization must be valid
            self.add_rule(
                field='hp_other_md01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 522: Other health problem hospitalization days must be positive
            self.add_rule(
                field='hp_other_md01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 523: ANC care at Day 01 must be valid
            self.add_rule(
                field='anc_care_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for ANC care',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 524: First ANC date at Day 01 cannot be future
            self.add_rule(
                field='date_anc_first_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='First ANC date cannot be in the future',
                suggestion='Correct the ANC visit date',
                severity='Critical'
            )
            
            # Rule 525: First ANC date at Day 01 must be after 2019
            self.add_rule(
                field='date_anc_first_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='First ANC date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 526: First ANC date should be before delivery date
            # Cross-field validation
            
            # Rule 527: Number of ANC visits must be at least 1
            self.add_rule(
                field='num_anc_visits_md01',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Number of ANC visits must be at least 1',
                suggestion='Enter a positive number of visits',
                severity='Warning'
            )
            
            # Rule 528: Iron pills during ANC must be valid
            self.add_rule(
                field='tr_fe_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for iron pills',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 529: Tetanus toxoid vaccine during ANC must be valid
            self.add_rule(
                field='tr_tetanus_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for tetanus toxoid vaccine',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 530: TT vaccination doses must be valid
            self.add_rule(
                field='errors_ttvac1',
                validation_func=lambda x: x in ['a', 'b', 'c', 'd'] if x and str(x).strip() else True,
                error_msg='Invalid TT vaccination dose count',
                suggestion='Select 1, 2, 3, or 4',
                severity='Warning'
            )
            
            # Rule 531: Previous TT vaccination must be valid
            self.add_rule(
                field='errors_wttv',
                validation_func=lambda x: x in ['1', '2'] if x and str(x).strip() else True,
                error_msg='Invalid response for previous TT vaccination',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 532: Total TT vaccinations must be positive
            self.add_rule(
                field='errors_hwtt',
                validation_func=lambda x: int(x) >= 0 if x and str(x).strip() else True,
                error_msg='Total TT vaccinations cannot be negative',
                suggestion='Enter a non-negative number',
                severity='Warning'
            )
            
            # Rule 533: Last TT vaccination date cannot be future
            self.add_rule(
                field='errors_ttv_date',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Last TT vaccination date cannot be in the future',
                suggestion='Correct the vaccination date',
                severity='Critical'
            )
            
            # Rule 534: Last TT vaccination date must be after 2019
            self.add_rule(
                field='errors_ttv_date',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Last TT vaccination date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 535: Folic acid during ANC must be valid
            self.add_rule(
                field='tr_folic_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for folic acid',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 536: Vitamins during ANC must be valid
            self.add_rule(
                field='tr_vitamins_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for vitamins',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 537: HIV test during ANC must be valid
            self.add_rule(
                field='tr_hivtest_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for HIV test',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 538: HIV test result must be valid
            self.add_rule(
                field='tr_hivtest_result_md01',
                validation_func=lambda x: x in ['CH00210', 'CH00180', 'CH00204', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid HIV test result',
                suggestion='Select Positive, Negative, Indeterminate, or Unknown',
                severity='Critical'
            )
            
            # Rule 539: Syphilis test during ANC must be valid
            self.add_rule(
                field='tr_syphilis_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for syphilis test',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 540: Syphilis test result must be valid
            self.add_rule(
                field='tr_syphilis_result_md01',
                validation_func=lambda x: x in ['CH00210', 'CH00180', 'CH00204', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid syphilis test result',
                suggestion='Select Positive, Negative, Indeterminate, or Unknown',
                severity='Critical'
            )
            
            # Rule 541: Syphilis treatment must be valid
            self.add_rule(
                field='tr_syphilis_trmt_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for syphilis treatment',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 542: Blood pressure measurement during ANC must be valid
            self.add_rule(
                field='tr_bp_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for blood pressure measurement',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 543: IPTp during ANC must be valid
            self.add_rule(
                field='tr_iptp_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for IPTp',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 544: Bednet during ANC must be valid
            self.add_rule(
                field='tr_bednet_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for bednet',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 545: Urine test for protein during ANC must be valid
            self.add_rule(
                field='tr_urineprotein_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for urine protein test',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 546: Other ANC care must be valid
            self.add_rule(
                field='tr_otheranc_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other ANC care',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 547: Other ANC care specification required when Yes selected
            self.add_rule(
                field='tr_otheranc_specify_md01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other ANC care specification required when "Yes" selected',
                suggestion='Specify the other type of care',
                severity='Critical'
            )
            
            # Rule 548: Other ANC care specification length
            self.add_rule(
                field='tr_otheranc_specify_md01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='ANC care specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 549: Ultrasound during ANC must be valid
            self.add_rule(
                field='tr_us_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for ultrasound',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 550: First trimester ultrasound selected
            # Checkbox field
            
            # Rule 551: Second trimester ultrasound selected
            # Checkbox field
            
            # Rule 552: Third trimester ultrasound selected
            # Checkbox field
            
            # Rule 553: Labor ultrasound selected
            # Checkbox field
            
            # Rule 554: First trimester ultrasound date cannot be future
            self.add_rule(
                field='date_us_tri1',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='First trimester ultrasound date cannot be in the future',
                suggestion='Correct the ultrasound date',
                severity='Critical'
            )
            
            # Rule 555: First trimester ultrasound date must be after 2019
            self.add_rule(
                field='date_us_tri1',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='First trimester ultrasound date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 556: Second trimester ultrasound date cannot be future
            self.add_rule(
                field='date_us_tri2',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Second trimester ultrasound date cannot be in the future',
                suggestion='Correct the ultrasound date',
                severity='Critical'
            )
            
            # Rule 557: Second trimester ultrasound date must be after 2019
            self.add_rule(
                field='date_us_tri2',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Second trimester ultrasound date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 558: Third trimester ultrasound date cannot be future
            self.add_rule(
                field='date_us_tri3',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Third trimester ultrasound date cannot be in the future',
                suggestion='Correct the ultrasound date',
                severity='Critical'
            )
            
            # Rule 559: Third trimester ultrasound date must be after 2019
            self.add_rule(
                field='date_us_tri3',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Third trimester ultrasound date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 560: Labor ultrasound date cannot be future
            self.add_rule(
                field='date_us_labor',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Labor ultrasound date cannot be in the future',
                suggestion='Correct the ultrasound date',
                severity='Critical'
            )
            
            # Rule 561: Labor ultrasound date must be after 2019
            self.add_rule(
                field='date_us_labor',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Labor ultrasound date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 562: Gestational age by ultrasound weeks must be positive
            self.add_rule(
                field='gestage_wk_us_md01',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Gestational age by ultrasound weeks must be at least 1',
                suggestion='Enter a valid gestational age in weeks',
                severity='Critical'
            )
            
            # Rule 563: Gestational age by ultrasound weeks must be ≤ 52
            self.add_rule(
                field='gestage_wk_us_md01',
                validation_func=lambda x: int(x) <= 52 if x and str(x).strip() else True,
                error_msg='Gestational age by ultrasound weeks cannot exceed 52',
                suggestion='Enter a valid gestational age',
                severity='Critical'
            )
            
            # Rule 564: Gestational age by ultrasound days must be between 0-6
            self.add_rule(
                field='gestage_day_us_md01',
                validation_func=lambda x: 0 <= int(x) <= 6 if x and str(x).strip() else True,
                error_msg='Gestational age by ultrasound days must be between 0 and 6',
                suggestion='Enter a value between 0 and 6 days',
                severity='Critical'
            )
            
            # Rule 565: Anemia diagnosis at Day 01 must be valid
            self.add_rule(
                field='anemia_diag_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia diagnosis',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 566: Anemia test at Day 01 must be valid
            self.add_rule(
                field='anemia_test_md01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for anemia test',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 567: Hemoglobin value at Day 01 must be positive
            self.add_rule(
                field='hemog_value_md01',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Hemoglobin must be a positive number',
                suggestion='Enter a valid hemoglobin level',
                severity='Warning'
            )
            
            # Rule 568: Hemoglobin value at Day 01 must be reasonable (2-20 g/dL)
            self.add_rule(
                field='hemog_value_md01',
                validation_func=lambda x: 2 <= float(x) <= 20 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Hemoglobin value seems unreasonable',
                suggestion='Verify hemoglobin is between 2-20 g/dL',
                severity='Warning'
            )
            
            # Rule 569: Hemoglobin unit at Day 01 must be valid
            self.add_rule(
                field='hemog_unit_md01',
                validation_func=lambda x: x in ['CH02333', 'CH02334'] if x and str(x).strip() else True,
                error_msg='Invalid hemoglobin unit',
                suggestion='Select g/dL or mmol/L',
                severity='Warning'
            )
            
            # Rule 570: Hemoglobin date at Day 01 cannot be future
            self.add_rule(
                field='date_hemog_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Hemoglobin measurement date cannot be in the future',
                suggestion='Correct the hemoglobin measurement date',
                severity='Critical'
            )
            
            # Rule 571: Hemoglobin date at Day 01 must be after 2019
            self.add_rule(
                field='date_hemog_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Hemoglobin measurement date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 572: Multiple delivery must be valid
            self.add_rule(
                field='multi_delivery',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for multiple delivery',
                suggestion='Select Yes, No, or Unknown',
                severity='Critical'
            )
            
            # Rule 573: Number of babies must be between 2-6 for multiple births
            self.add_rule(
                field='num_babies',
                validation_func=lambda x: 2 <= int(x) <= 6 if x and str(x).strip() else True,
                error_msg='Number of babies must be between 2 and 6 for multiple births',
                suggestion='Enter a number between 2 and 6',
                severity='Critical'
            )
            
            # Rule 574: Outcome ID 1 format must be valid
            self.add_rule(
                field='outcome_id_1',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_1)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 575: Outcome ID 2 format must be valid
            self.add_rule(
                field='outcome_id_2',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_2)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 576: Outcome ID 3 format must be valid
            self.add_rule(
                field='outcome_id_3',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_3)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 577: Outcome ID 4 format must be valid
            self.add_rule(
                field='outcome_id_4',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_4)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 578: Outcome ID 5 format must be valid
            self.add_rule(
                field='outcome_id_5',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_5)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 579: Outcome ID 6 format must be valid
            self.add_rule(
                field='outcome_id_6',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_6)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 580: Maternal health card source selected for Day 01
            # Checkbox field
            
            # Rule 581: Antenatal care records source selected for Day 01
            # Checkbox field
            
            # Rule 582: Delivery records source selected for Day 01
            # Checkbox field
            
            # Rule 583: Interview with mother source selected for Day 01
            # Checkbox field
            
            # Rule 584: Other form source specification required when selected
            self.add_rule(
                field='form_source_md01_other',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other form source specification required',
                suggestion='Specify the other data source',
                severity='Critical'
            )
            
            # Rule 585: Other form source length
            self.add_rule(
                field='form_source_md01_other',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Form source specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 586: Day 01 form completion date cannot be future
            self.add_rule(
                field='date_form_complete_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Day 01 form completion date cannot be in the future',
                suggestion='Correct the form completion date',
                severity='Critical'
            )
            
            # Rule 587: Day 01 form completion date must be after 2019
            self.add_rule(
                field='date_form_complete_md01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Day 01 form completion date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 588: Day 01 form completion date should be after delivery date
            # Cross-field validation
            
            # Rule 589: Number of stillbirths components should sum correctly
            # Cross-field validation
            
            # Rule 590: Number of live births components should sum correctly
            # Cross-field validation
            
            # Rule 591: Number of children calculations should be consistent
            # Cross-field validation
            
            # Rule 592: Hospitalization days should be provided when admitted
            # Cross-field validation
            
            # Rule 593: Abruption percentage should be provided when abruption present
            # Cross-field validation
            
            # Rule 594: HIV test result should be provided when test done
            # Cross-field validation
            
            # Rule 595: Syphilis test result should be provided when test done
            # Cross-field validation
            
            # Rule 596: Syphilis treatment should be provided when test positive
            # Cross-field validation
            
            # Rule 597: Ultrasound dates should match trimesters selected
            # Cross-field validation
            
            # Rule 598: Multiple outcome IDs should be sequential
            # Cross-field validation
            
            # Rule 599: Outcome IDs should match number of babies
            # Cross-field validation
            
            # Rule 600: Helper method for float validation
            # This is a utility method, not a rule
            # Cross-field validation
                    # =============================================================================
        # BATCH 7: DAY 01 BABY FORM - DELIVERY & INITIAL CARE (Rules 601-700)
        # =============================================================================

            # Rule 601: Day 01 baby context with Day 42 must be valid
            self.add_rule(
                field='context_bd01_to_bd42',
                validation_func=lambda x: x in ['CH00001', 'CH00002'] if x and str(x).strip() else True,
                error_msg='Invalid response for Day 01 baby form completion timing with Day 42',
                suggestion='Select Yes or No',
                severity='Warning'
            )
            
            # Rule 602: Day 01 baby GPS Latitude format must be valid
            self.add_rule(
                field='gps_day01_bay',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS latitude format',
                suggestion='Enter a valid latitude coordinate (e.g., 9.3122)',
                severity='Warning'
            )
            
            # Rule 603: Day 01 baby GPS Latitude range must be valid for Ethiopia
            self.add_rule(
                field='gps_day01_bay',
                validation_func=lambda x: 3.0 <= float(x) <= 15.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS latitude outside expected range for Ethiopia',
                suggestion='Latitude should be between 3°N and 15°N',
                severity='Warning'
            )
            
            # Rule 604: Day 01 baby GPS Longitude format must be valid
            self.add_rule(
                field='gpslong_day01baby',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS longitude format',
                suggestion='Enter a valid longitude coordinate (e.g., 42.1234)',
                severity='Warning'
            )
            
            # Rule 605: Day 01 baby GPS Longitude range must be valid for Ethiopia
            self.add_rule(
                field='gpslong_day01baby',
                validation_func=lambda x: 33.0 <= float(x) <= 48.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS longitude outside expected range for Ethiopia',
                suggestion='Longitude should be between 33°E and 48°E',
                severity='Warning'
            )
            
            # Rule 606: Baby outcome ID format must be valid
            self.add_rule(
                field='outcome_id_bd01',
                validation_func=lambda x: re.match(r'^[A-Z0-9]+_\d+$', str(x)) and len(str(x)) <= 11 if x and str(x).strip() else True,
                error_msg='Baby outcome ID must be in format: CHAMPS_ID_# (e.g., TSAA00056_1)',
                suggestion='Use the format with underscore followed by child number',
                severity='Critical'
            )
            
            # Rule 607: Baby outcome ID should match maternal outcome ID pattern
            # Cross-field validation
            
            # Rule 608: DSS baby ID length validation
            self.add_rule(
                field='dss_baby_bd01',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='DSS baby ID exceeds maximum length of 50 characters',
                suggestion='Truncate or verify the DSS ID',
                severity='Warning'
            )
            
            # Rule 609: Pregnancy outcome must be valid
            self.add_rule(
                field='preg_outcome',
                validation_func=lambda x: x in ['CH02448', 'CH02446', 'CH02447', 'CH01119', 'CH02444', 
                                            'CH02443', 'CH02445', 'CH02442', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid pregnancy outcome',
                suggestion='Select a valid pregnancy outcome from the list',
                severity='Critical'
            )
            
            # Rule 610: Gestational age known must be valid
            self.add_rule(
                field='gestage_known_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for gestational age known',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 611: Baby gestational age weeks must be between 0-52
            self.add_rule(
                field='gestage_wk_bd01',
                validation_func=lambda x: 0 <= int(x) <= 52 if x and str(x).strip() else True,
                error_msg='Gestational age weeks must be between 0 and 52',
                suggestion='Enter a valid gestational age in weeks',
                severity='Critical'
            )
            
            # Rule 612: Baby gestational age weeks must be integer
            self.add_rule(
                field='gestage_wk_bd01',
                validation_func=lambda x: str(x).isdigit() if x and str(x).strip() else True,
                error_msg='Gestational age weeks must be a whole number',
                suggestion='Enter a whole number of weeks',
                severity='Critical'
            )
            
            # Rule 613: Baby gestational age days must be between 0-7
            self.add_rule(
                field='gestage_day_bd01',
                validation_func=lambda x: 0 <= int(x) <= 7 if x and str(x).strip() else True,
                error_msg='Gestational age days must be between 0 and 7',
                suggestion='Enter a value between 0 and 7 days',
                severity='Critical'
            )
            
            # Rule 614: Baby gestational age days must be integer
            self.add_rule(
                field='gestage_day_bd01',
                validation_func=lambda x: str(x).isdigit() if x and str(x).strip() else True,
                error_msg='Gestational age days must be a whole number',
                suggestion='Enter a whole number of days',
                severity='Critical'
            )
            
            # Rule 615: Baby sex must be valid
            self.add_rule(
                field='sex',
                validation_func=lambda x: x in ['CH00031', 'CH00030', 'CH00032', 'CH00033'] if x and str(x).strip() else True,
                error_msg='Invalid sex value',
                suggestion='Select Female, Male, Indeterminate, or Unknown',
                severity='Critical'
            )
            
            # Rule 616: Baby delivery date type must be valid
            self.add_rule(
                field='date_delivery_type_bd01',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid baby delivery date type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 617: Baby delivery date cannot be future
            self.add_rule(
                field='date_delivery_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Baby delivery date cannot be in the future',
                suggestion='Correct the delivery date',
                severity='Critical'
            )
            
            # Rule 618: Baby delivery date must be after 2019
            self.add_rule(
                field='date_delivery_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Baby delivery date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 619: Baby delivery date should match maternal delivery date
            # Cross-field validation
            
            # Rule 620: Baby delivery time type must be valid
            self.add_rule(
                field='time_delivery_type_bd01',
                validation_func=lambda x: x in ['CH00984', 'CH00985', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid baby delivery time type',
                suggestion='Select Exact, Approximate, or Unknown',
                severity='Warning'
            )
            
            # Rule 621: Baby delivery time format must be valid
            self.add_rule(
                field='time_delivery_bd01',
                validation_func=lambda x: re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid time format',
                suggestion='Use HH:MM format (24-hour)',
                severity='Warning'
            )
            
            # Rule 622: Delivery method must be valid
            self.add_rule(
                field='delivery_method',
                validation_func=lambda x: x in ['CH01006', 'CH01150', 'CH01007', 'CH02391', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid delivery method',
                suggestion='Select a valid delivery method from the list',
                severity='Critical'
            )
            
            # Rule 623: C-section timing must be valid
            self.add_rule(
                field='csection_timing',
                validation_func=lambda x: x in ['CH01186', 'CH01187', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid C-section timing',
                suggestion='Select before labor, during labor, or unknown',
                severity='Warning'
            )
            
            # Rule 624: C-section indication should not be empty
            self.add_rule(
                field='csection_indication',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='C-section indication is required',
                suggestion='Enter the primary indication for C-section',
                severity='Critical'
            )
            
            # Rule 625: C-section indication length
            self.add_rule(
                field='csection_indication',
                validation_func=lambda x: len(str(x)) <= 4000 if x and str(x).strip() else True,
                error_msg='C-section indication exceeds 4000 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 626: C-section emergent must be valid
            self.add_rule(
                field='csection_emergent',
                validation_func=lambda x: x in ['CH01151', 'CH02452', 'CH01152', 'CH01153'] if x and str(x).strip() else True,
                error_msg='Invalid C-section type',
                suggestion='Select emergency, non-emergent, elective, or unspecified',
                severity='Warning'
            )
            
            # Rule 627: Birth weight known must be valid
            self.add_rule(
                field='birth_weight_known',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for birth weight known',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 628: Birth weight value must be positive
            self.add_rule(
                field='birth_weight_value',
                validation_func=lambda x: int(x) > 0 if x and str(x).strip() else True,
                error_msg='Birth weight must be a positive number',
                suggestion='Enter a valid birth weight in grams',
                severity='Warning'
            )
            
            # Rule 629: Birth weight value must be reasonable (300-6000 grams)
            self.add_rule(
                field='birth_weight_value',
                validation_func=lambda x: 300 <= int(x) <= 6000 if x and str(x).strip() else True,
                error_msg='Birth weight value seems unreasonable',
                suggestion='Verify birth weight is between 300-6000 grams',
                severity='Warning'
            )
            
            # Rule 630: Birth weight date cannot be future
            self.add_rule(
                field='date_birth_weight_aprox',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Birth weight date cannot be in the future',
                suggestion='Correct the weight measurement date',
                severity='Critical'
            )
            
            # Rule 631: Birth weight date must be after 2019
            self.add_rule(
                field='date_birth_weight_aprox',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Birth weight date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 632: Birth weight date should be close to delivery date
            # Cross-field validation
            
            # Rule 633: Birth weight estimate must be valid
            self.add_rule(
                field='birth_weight_est',
                validation_func=lambda x: x in ['CH02438', 'CH02439', 'CH02440', 'CH02441', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid birth weight estimate',
                suggestion='Select a weight category from the list',
                severity='Warning'
            )
            
            # Rule 634: Meconium present must be valid
            self.add_rule(
                field='meconium_present',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for meconium presence',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 635: Baby dried and rubbed after delivery must be valid
            self.add_rule(
                field='tr_dry_and_rub_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for drying and rubbing',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 636: Baby received suction must be valid
            self.add_rule(
                field='tr_suction_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for suction',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 637: Baby received help to breathe must be valid
            self.add_rule(
                field='tr_help_breath_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for resuscitation',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 638: Baby placed on chest must be valid
            self.add_rule(
                field='tr_placed_on_chest_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for skin-to-skin contact',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 639: Baby breastfed within 1 hour must be valid
            self.add_rule(
                field='tr_breast_feed_1hr_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for early breastfeeding',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 640: Baby bathed within 6 hours must be valid
            self.add_rule(
                field='tr_baby_bath_6hr_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for early bathing',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 641: Baby antibiotics must be valid
            self.add_rule(
                field='tr_antibiot_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for antibiotics',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 642: Baby CPAP must be valid
            self.add_rule(
                field='tr_cpap_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for CPAP',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 643: Baby oxygen must be valid
            self.add_rule(
                field='tr_oxygen_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for oxygen',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 644: Baby mechanical ventilation must be valid
            self.add_rule(
                field='tr_ventalation_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for mechanical ventilation',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 645: Baby eye ointment must be valid
            self.add_rule(
                field='tr_eyeoint_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for eye ointment',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 646: Baby cord care must be valid
            self.add_rule(
                field='tr_cordcare_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for cord care',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 647: Baby vitamin K must be valid
            self.add_rule(
                field='tr_vit_k_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for vitamin K',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 648: Baby NICU admission must be valid
            self.add_rule(
                field='tr_nicu_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for NICU admission',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 649: Other baby treatment must be valid
            self.add_rule(
                field='tr_other_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other treatment',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 650: Other baby treatment specification required when Yes selected
            self.add_rule(
                field='tr_other_specify_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other baby treatment specification required when "Yes" selected',
                suggestion='Specify the other treatment',
                severity='Critical'
            )
            
            # Rule 651: Other baby treatment specification length
            self.add_rule(
                field='tr_other_specify_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Treatment specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 652: Baby Kangaroo Mother Care must be valid
            self.add_rule(
                field='tr_kmc_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for Kangaroo Mother Care',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 653: Fetal distress must be valid
            self.add_rule(
                field='hp_distress_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for fetal distress',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 654: Fetal distress hospitalization must be valid
            self.add_rule(
                field='hp_distress_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for fetal distress hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 655: Fetal distress hospitalization days must be positive
            self.add_rule(
                field='hp_distress_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 656: Knot in umbilical cord must be valid
            self.add_rule(
                field='hp_ucknot_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for knot in umbilical cord',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 657: Knot in umbilical cord hospitalization must be valid
            self.add_rule(
                field='hp_ucknot_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for cord knot hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 658: Knot in umbilical cord hospitalization days must be positive
            self.add_rule(
                field='hp_ucknot_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 659: Neural tube defect must be valid
            self.add_rule(
                field='hp_ntube_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for neural tube defect',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 660: Neural tube defect hospitalization must be valid
            self.add_rule(
                field='hp_ntube_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for neural tube defect hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 661: Neural tube defect hospitalization days must be positive
            self.add_rule(
                field='hp_ntube_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 662: Abdominal wall defect must be valid
            self.add_rule(
                field='hp_abwall_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for abdominal wall defect',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 663: Abdominal wall defect hospitalization must be valid
            self.add_rule(
                field='hp_abwall_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for abdominal wall defect hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 664: Abdominal wall defect hospitalization days must be positive
            self.add_rule(
                field='hp_abwall_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 665: Other birth defect must be valid
            self.add_rule(
                field='hp_bdefectoth_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other birth defect',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 666: Other birth defect specification required when Yes selected
            self.add_rule(
                field='hp_bdefectoth_spec_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other birth defect specification required when "Yes" selected',
                suggestion='Specify the birth defect',
                severity='Critical'
            )
            
            # Rule 667: Other birth defect specification length
            self.add_rule(
                field='hp_bdefectoth_spec_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Birth defect specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 668: Other birth defect hospitalization must be valid
            self.add_rule(
                field='hp_bdefectoth_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for birth defect hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 669: Other birth defect hospitalization days must be positive
            self.add_rule(
                field='hp_bdefectoth_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 670: Congenital syphilis must be valid
            self.add_rule(
                field='hp_cogsyph_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for congenital syphilis',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 671: Congenital syphilis hospitalization must be valid
            self.add_rule(
                field='hp_cogsyph_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for congenital syphilis hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 672: Congenital syphilis hospitalization days must be positive
            self.add_rule(
                field='hp_cogsyph_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 673: Breathing difficulties at birth must be valid
            self.add_rule(
                field='hp_difbrth_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for breathing difficulties',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 674: Breathing difficulties hospitalization must be valid
            self.add_rule(
                field='hp_difbrth_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for breathing difficulties hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 675: Breathing difficulties hospitalization days must be positive
            self.add_rule(
                field='hp_difbrth_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 676: Breathed weakly or did not cry must be valid
            self.add_rule(
                field='hp_brthweak_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for weak breathing/no cry',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 677: Weak breathing hospitalization must be valid
            self.add_rule(
                field='hp_brthweak_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for weak breathing hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 678: Weak breathing hospitalization days must be positive
            self.add_rule(
                field='hp_brthweak_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 679: Seizures <24 hours must be valid
            self.add_rule(
                field='hp_seiz24_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for early seizures',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 680: Early seizures hospitalization must be valid
            self.add_rule(
                field='hp_seiz24_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for early seizures hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 681: Early seizures hospitalization days must be positive
            self.add_rule(
                field='hp_seiz24_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 682: Seizures 24-48 hours must be valid
            self.add_rule(
                field='hp_seiz48_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for late seizures',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 683: Late seizures hospitalization must be valid
            self.add_rule(
                field='hp_seiz48_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for late seizures hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 684: Late seizures hospitalization days must be positive
            self.add_rule(
                field='hp_seiz48_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 685: Fever or low temperature must be valid
            self.add_rule(
                field='hp_temp_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for fever/low temperature',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 686: Fever hospitalization must be valid
            self.add_rule(
                field='hp_temp_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for fever hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 687: Fever hospitalization days must be positive
            self.add_rule(
                field='hp_temp_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 688: Pneumonia signs must be valid
            self.add_rule(
                field='hp_pnasigns_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for pneumonia signs',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 689: Pneumonia hospitalization must be valid
            self.add_rule(
                field='hp_pnasigns_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for pneumonia hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 690: Pneumonia hospitalization days must be positive
            self.add_rule(
                field='hp_pnasigns_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 691: Pus from umbilical stump must be valid
            self.add_rule(
                field='hp_ucpus_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for pus from umbilical stump',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 692: Pus from umbilical stump hospitalization must be valid
            self.add_rule(
                field='hp_ucpus_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for umbilical pus hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 693: Pus from umbilical stump hospitalization days must be positive
            self.add_rule(
                field='hp_ucpus_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 694: Jaundice must be valid
            self.add_rule(
                field='hp_jaundice_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for jaundice',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 695: Jaundice hospitalization must be valid
            self.add_rule(
                field='hp_jaundice_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for jaundice hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 696: Jaundice hospitalization days must be positive
            self.add_rule(
                field='hp_jaundice_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 697: Feeding difficulty must be valid
            self.add_rule(
                field='hp_feeddiff_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for feeding difficulty',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 698: Feeding difficulty hospitalization must be valid
            self.add_rule(
                field='hp_feeddiff_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for feeding difficulty hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 699: Feeding difficulty hospitalization days must be positive
            self.add_rule(
                field='hp_feeddiff_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 700: COVID exposure in baby must be valid
            self.add_rule(
                field='hp_covidex_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
        )
            def add_rule(self, field, validation_func, error_msg, suggestion, severity='Warning'):
                """Add a validation rule with severity level"""
                self.rules.append({
                    'field': field,
                    'func': validation_func,
                    'error_msg': error_msg,
                    'suggestion': suggestion,
                    'severity': severity
                })
            # =============================================================================
    # BATCH 8: DAY 01 BABY FORM - CONTINUED & DAY 42 MATERNAL FORM (Rules 701-800)
    # =============================================================================

            # Rule 701: Baby COVID exposure hospitalization must be valid
            self.add_rule(
                field='hp_covidex_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID exposure hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 702: Baby COVID exposure hospitalization days must be positive
            self.add_rule(
                field='hp_covidex_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 703: Baby COVID diagnosis must be valid
            self.add_rule(
                field='hp_covid_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 704: Baby COVID diagnosis hospitalization must be valid
            self.add_rule(
                field='hp_covid_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for COVID diagnosis hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 705: Baby COVID diagnosis hospitalization days must be positive
            self.add_rule(
                field='hp_covid_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 706: Other baby health problem must be valid
            self.add_rule(
                field='hp_other_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 707: Other baby health problem specification required when Yes selected
            self.add_rule(
                field='hp_other_specify_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other baby health problem specification required when "Yes" selected',
                suggestion='Specify the other health problem',
                severity='Critical'
            )
            
            # Rule 708: Other baby health problem specification length
            self.add_rule(
                field='hp_other_specify_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Health problem specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 709: Other baby health problem hospitalization must be valid
            self.add_rule(
                field='hp_other_bd01_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for other health problem hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 710: Other baby health problem hospitalization days must be positive
            self.add_rule(
                field='hp_other_bd01_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 711: Baby mortality status must be valid
            self.add_rule(
                field='mortality_baby_bd01',
                validation_func=lambda x: x in ['CH02404', 'CH02405', 'CH02406', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid baby health status',
                suggestion='Select Alive and well, Alive with problems, Deceased, or Unknown',
                severity='Critical'
            )
            
            # Rule 712: Baby death date cannot be future
            self.add_rule(
                field='date_dod_baby_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Baby death date cannot be in the future',
                suggestion='Correct the death date',
                severity='Critical'
            )
            
            # Rule 713: Baby death date must be after 2019
            self.add_rule(
                field='date_dod_baby_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Baby death date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 714: Baby death date should be after delivery date
            # Cross-field validation
            
            # Rule 715: Baby enrolled in CHAMPS mortality surveillance must be valid
            self.add_rule(
                field='champs_bd01',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for CHAMPS mortality enrollment',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 716: CHAMPS Mortality ID must be exactly 9 digits
            self.add_rule(
                field='champs_id_mort_bd01',
                validation_func=lambda x: len(str(x).strip()) == 9 if x and str(x).strip() else True,
                error_msg='CHAMPS Mortality ID must be exactly 9 digits',
                suggestion='Enter a valid 9-digit CHAMPS Mortality ID',
                severity='Critical'
            )
            
            # Rule 717: Baby cause of death must be valid
            self.add_rule(
                field='cod_bd01',
                validation_func=lambda x: x in ['CH02429', 'CH02430', 'CH02431', 'CH02432', 'CH00010', 
                                            'CH02434', 'CH01121', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid baby cause of death',
                suggestion='Select a valid cause of death from the list',
                severity='Critical'
            )
            
            # Rule 718: Other baby cause of death specification required when "Other" selected
            self.add_rule(
                field='cod_other_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other cause of death specification required',
                suggestion='Specify the cause of death',
                severity='Critical'
            )
            
            # Rule 719: Other baby cause of death length
            self.add_rule(
                field='cod_other_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Cause of death specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 720: Clinical record as COD source selected
            # Checkbox field
            
            # Rule 721: Death certificate as COD source selected
            # Checkbox field
            
            # Rule 722: Verbal autopsy as COD source selected
            # Checkbox field
            
            # Rule 723: Family member as COD source selected
            # Checkbox field
            
            # Rule 724: Other COD source specification required when selected
            self.add_rule(
                field='cod_source_other_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other COD source specification required',
                suggestion='Specify the other source of information',
                severity='Critical'
            )
            
            # Rule 725: Other COD source length
            self.add_rule(
                field='cod_source_other_bd01',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='COD source specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 726: Baby death location must be valid
            self.add_rule(
                field='cod_location_bd01',
                validation_func=lambda x: x in ['CH00012', 'CH00013', 'CH00014', 'CH00015', 'CH00016',
                                            'CH01839', 'CH01841', 'CH00017', 'CH00003'] 
                                        if x and str(x).strip() else True,
                error_msg='Invalid baby death location',
                suggestion='Select a valid location from the list',
                severity='Critical'
            )
            
            # Rule 727: Baby death facility must be valid when facility selected
            self.add_rule(
                field='cod_facility_bd01',
                validation_func=lambda x: x in ['CH02648', 'CH02654', 'CH02652', 'CH02647', 'CH02646', 'CH01998',
                                            'CH02730', 'CH02651', 'CH02649', 'CH02650', 'CH02635', 'CH02637',
                                            'CH02634', 'CH02643', 'CH02642', 'CH02639', 'CH02640', 'CH02002',
                                            'CH02633', 'CH02638', 'CH02644', 'CH02636', 'CH02641', 'CH01995',
                                            'CH01996', 'CH01997', 'CH02007', 'CH02008', 'CH02009', 'CH02645',
                                            'CH01857', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid baby death facility',
                suggestion='Select a valid health facility from the list',
                severity='Critical'
            )
            
            # Rule 728: Other baby death facility specification required when "Other" selected
            self.add_rule(
                field='cod_facility_oth_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other baby death facility specification required',
                suggestion='Specify the facility where baby died',
                severity='Critical'
            )
            
            # Rule 729: Other baby death facility length
            self.add_rule(
                field='cod_facility_oth_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Facility specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 730: Other baby death location specification required when "Other" selected
            self.add_rule(
                field='cod_location_oth_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other baby death location specification required',
                suggestion='Specify the location where baby died',
                severity='Critical'
            )
            
            # Rule 731: Other baby death location length
            self.add_rule(
                field='cod_location_oth_bd01',
                validation_func=lambda x: len(str(x)) <= 100 if x and str(x).strip() else True,
                error_msg='Location specification exceeds 100 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 732: Day 42 follow-up visit must be valid
            self.add_rule(
                field='d42_visit_ok',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for Day 42 follow-up',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 733: Day 42 visit date cannot be future
            self.add_rule(
                field='date_d42_visit',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Day 42 visit date cannot be in the future',
                suggestion='Correct the scheduled visit date',
                severity='Critical'
            )
            
            # Rule 734: Day 42 visit date must be after 2019
            self.add_rule(
                field='date_d42_visit',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Day 42 visit date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # Rule 735: Day 42 visit date should be about 42 days after delivery
            # Cross-field validation
            
            # Rule 736: Day 42 visit time preference must be valid
            self.add_rule(
                field='d42_visit_time',
                validation_func=lambda x: x in ['CH02410', 'CH02411', 'CH02412'] if x and str(x).strip() else True,
                error_msg='Invalid time of day preference',
                suggestion='Select Morning, Afternoon, or Evening',
                severity='Warning'
            )
            
            # Rule 737: Child clinical record as source selected
            # Checkbox field
            
            # Rule 738: Maternal health card as source selected
            # Checkbox field
            
            # Rule 739: Antenatal care records as source selected
            # Checkbox field
            
            # Rule 740: Delivery records as source selected
            # Checkbox field
            
            # Rule 741: Interview with mother as source selected
            # Checkbox field
            
            # Rule 742: Other form source specification required when selected
            self.add_rule(
                field='form_source_other_bd01',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Other form source specification required',
                suggestion='Specify the other data source',
                severity='Critical'
            )
            
            # Rule 743: Other form source length
            self.add_rule(
                field='form_source_other_bd01',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Form source specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 744: Day 01 baby form completion date cannot be future
            self.add_rule(
                field='date_form_complete_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x and str(x).strip() else True,
                error_msg='Day 01 baby form completion date cannot be in the future',
                suggestion='Correct the form completion date',
                severity='Critical'
            )
            
            # Rule 745: Day 01 baby form completion date must be after 2019
            self.add_rule(
                field='date_form_complete_bd01',
                validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') >= datetime(2019, 1, 1) if x and str(x).strip() else True,
                error_msg='Day 01 baby form completion date must be after 2019-01-01',
                suggestion='Enter a valid date',
                severity='Warning'
            )
            
            # =========================================================================
            # DAY 42 MATERNAL FORM RULES
            # =========================================================================
            
            # Rule 746: Day 42 GPS Latitude format must be valid
            self.add_rule(
                field='gps_at_day42',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS latitude format',
                suggestion='Enter a valid latitude coordinate (e.g., 9.3122)',
                severity='Warning'
            )
            
            # Rule 747: Day 42 GPS Latitude range must be valid for Ethiopia
            self.add_rule(
                field='gps_at_day42',
                validation_func=lambda x: 3.0 <= float(x) <= 15.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS latitude outside expected range for Ethiopia',
                suggestion='Latitude should be between 3°N and 15°N',
                severity='Warning'
            )
            
            # Rule 748: Day 42 GPS Longitude format must be valid
            self.add_rule(
                field='gpslong_day42m',
                validation_func=lambda x: re.match(r'^-?\d+\.?\d*$', str(x)) if x and str(x).strip() else True,
                error_msg='Invalid GPS longitude format',
                suggestion='Enter a valid longitude coordinate (e.g., 42.1234)',
                severity='Warning'
            )
            
            # Rule 749: Day 42 GPS Longitude range must be valid for Ethiopia
            self.add_rule(
                field='gpslong_day42m',
                validation_func=lambda x: 33.0 <= float(x) <= 48.0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='GPS longitude outside expected range for Ethiopia',
                suggestion='Longitude should be between 33°E and 48°E',
                severity='Warning'
            )
            
            # Rule 750: Day 42 context must be valid
            self.add_rule(
                field='context_md42_to_all',
                validation_func=lambda x: x in ['CH02421', 'CH02422', 'CH02423'] if x and str(x).strip() else True,
                error_msg='Invalid form completion timing',
                suggestion='Select the appropriate option from the list',
                severity='Warning'
            )
            
            # Rule 751: Day 42 interviewer ID is required
            self.add_rule(
                field='interviewer_id_md42',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewer ID is required for Day 42 form',
                suggestion='Enter the interviewer ID',
                severity='Critical'
            )
            
            # Rule 752: Day 42 interviewee is mother must be valid
            self.add_rule(
                field='interview_mom_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for interviewee being the mother',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 753: Day 42 interviewee name required when not mother
            self.add_rule(
                field='interviewee_name_md42',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Interviewee name is required when interviewee is not the mother',
                suggestion='Enter the name of the person being interviewed',
                severity='Critical'
            )
            
            # Rule 754: Day 42 husband relationship selected
            # Checkbox field
            
            # Rule 755: Day 42 child relationship selected
            # Checkbox field
            
            # Rule 756: Day 42 mother relationship selected
            # Checkbox field
            
            # Rule 757: Day 42 father relationship selected
            # Checkbox field
            
            # Rule 758: Day 42 mother-in-law relationship selected
            # Checkbox field
            
            # Rule 759: Day 42 father-in-law relationship selected
            # Checkbox field
            
            # Rule 760: Day 42 aunt/uncle relationship selected
            # Checkbox field
            
            # Rule 761: Day 42 cousin relationship selected
            # Checkbox field
            
            # Rule 762: Day 42 other relationship specification required when selected
            self.add_rule(
                field='intview_relation_oth_md42',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Relationship specification required when "Other" is selected',
                suggestion='Specify the relationship to the mother',
                severity='Critical'
            )
            
            # Rule 763: Day 42 other relationship length
            self.add_rule(
                field='intview_relation_oth_md42',
                validation_func=lambda x: len(str(x)) <= 50 if x and str(x).strip() else True,
                error_msg='Relationship specification exceeds 50 characters',
                suggestion='Shorten the description',
                severity='Warning'
            )
            
            # Rule 764: Day 42 address change must be valid
            self.add_rule(
                field='address_chg_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for address change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 765: Day 42 updated address required when changed
            self.add_rule(
                field='address_md42',
                validation_func=lambda x: bool(x and str(x).strip()) if x is not None else True,
                error_msg='Updated address is required when address changed',
                suggestion='Enter the new address',
                severity='Critical'
            )
            
            # Rule 766: Day 42 phone change must be valid
            self.add_rule(
                field='phone_chg_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for phone change',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 767: Day 42 updated phone number length
            self.add_rule(
                field='phone_d42',
                validation_func=lambda x: len(re.sub(r'\D', '', str(x))) <= 10 if x and str(x).strip() else True,
                error_msg='Updated phone number exceeds 10 digits',
                suggestion='Remove dashes and ensure max 10 digits',
                severity='Warning'
            )
            
            # Rule 768: Day 42 updated phone number format
            self.add_rule(
                field='phone_d42',
                validation_func=lambda x: re.match(r'^\d{1,10}$', re.sub(r'\D', '', str(x))) if x and str(x).strip() else True,
                error_msg='Updated phone number must contain only digits',
                suggestion='Enter phone number without dashes',
                severity='Warning'
            )
            
            # Rule 769: Day 42 maternal mortality must be valid
            self.add_rule(
                field='mortality_mom_md42',
                validation_func=lambda x: x in ['CH02402', 'CH02403', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for maternal vital status',
                suggestion='Select Mother alive, deceased, or Unknown',
                severity='Critical'
            )
            
            # Rule 770: Day 42 weight known must be valid
            self.add_rule(
                field='weight_known_mom_md42',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for weight known',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 771: Day 42 weight value must be positive
            self.add_rule(
                field='weight_value_mom_md42',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Weight must be a positive number',
                suggestion='Enter a valid weight in kg',
                severity='Warning'
            )
            
            # Rule 772: Day 42 weight value must be reasonable (30-150 kg)
            self.add_rule(
                field='weight_value_mom_md42',
                validation_func=lambda x: 30 <= float(x) <= 150 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='Weight value seems unreasonable',
                suggestion='Verify weight is between 30-150 kg',
                severity='Warning'
            )
            
            # Rule 773: Day 42 weight method must be valid
            self.add_rule(
                field='weight_method_mom_md42',
                validation_func=lambda x: x in ['CH02372', 'CH02373', 'CH02374'] if x and str(x).strip() else True,
                error_msg='Invalid weight determination method',
                suggestion='Select measured, from documents, or self-report',
                severity='Warning'
            )
            
            # Rule 774: Day 42 MUAC known must be valid
            self.add_rule(
                field='muac_mom_known_md42',
                validation_func=lambda x: x in ['CH02332', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for MUAC known',
                suggestion='Select Known or Unknown',
                severity='Warning'
            )
            
            # Rule 775: Day 42 MUAC value must be positive
            self.add_rule(
                field='muac_mom_value_md42',
                validation_func=lambda x: float(x) > 0 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='MUAC must be a positive number',
                suggestion='Enter a valid MUAC in cm',
                severity='Warning'
            )
            
            # Rule 776: Day 42 MUAC value must be reasonable (10-50 cm)
            self.add_rule(
                field='muac_mom_value_md42',
                validation_func=lambda x: 10 <= float(x) <= 50 if x and str(x).strip() and self._is_float(x) else True,
                error_msg='MUAC value seems unreasonable',
                suggestion='Verify MUAC is between 10-50 cm',
                severity='Warning'
            )
            
            # Rule 777: Day 42 MUAC method must be valid
            self.add_rule(
                field='muac_mom_method_md42',
                validation_func=lambda x: x in ['CH02372', 'CH02373'] if x and str(x).strip() else True,
                error_msg='Invalid MUAC determination method',
                suggestion='Select measured or from documents',
                severity='Warning'
            )
            
            # Rule 778: Signs of obstetric fistula must be valid
            self.add_rule(
                field='hp_obsfist_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for obstetric fistula signs',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 779: Obstetric fistula hospitalization must be valid
            self.add_rule(
                field='hp_obsfist_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for fistula hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 780: Obstetric fistula hospitalization days must be positive
            self.add_rule(
                field='hp_obsfist_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 781: Signs of severe infection/sepsis must be valid
            self.add_rule(
                field='hp_infect_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for severe infection signs',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 782: Severe infection hospitalization must be valid
            self.add_rule(
                field='hp_infect_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for infection hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 783: Severe infection hospitalization days must be positive
            self.add_rule(
                field='hp_infect_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 784: Heavy bleeding after delivery (postpartum) must be valid
            self.add_rule(
                field='hp_bleedaft_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for postpartum bleeding',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 785: Postpartum bleeding hospitalization must be valid
            self.add_rule(
                field='hp_bleedaft_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for bleeding hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 786: Postpartum bleeding hospitalization days must be positive
            self.add_rule(
                field='hp_bleedaft_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 787: Hypertension at Day 42 must be valid
            self.add_rule(
                field='hp_highbp_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for hypertension',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 788: Hypertension hospitalization at Day 42 must be valid
            self.add_rule(
                field='hp_highbp_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for hypertension hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 789: Hypertension hospitalization days at Day 42 must be positive
            self.add_rule(
                field='hp_highbp_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 790: Pneumonia signs at Day 42 must be valid
            self.add_rule(
                field='hp_pnasigns_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for pneumonia signs',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 791: Pneumonia hospitalization at Day 42 must be valid
            self.add_rule(
                field='hp_pnasigns_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for pneumonia hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 792: Pneumonia hospitalization days at Day 42 must be positive
            self.add_rule(
                field='hp_pnasigns_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 793: Seizures at Day 42 must be valid
            self.add_rule(
                field='hp_seiz_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for seizures',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 794: Seizures hospitalization at Day 42 must be valid
            self.add_rule(
                field='hp_seiz_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for seizures hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 795: Seizures hospitalization days at Day 42 must be positive
            self.add_rule(
                field='hp_seiz_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 796: Malaria at Day 42 must be valid
            self.add_rule(
                field='hp_malaria_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for malaria',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 797: Malaria hospitalization at Day 42 must be valid
            self.add_rule(
                field='hp_malaria_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for malaria hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 798: Malaria hospitalization days at Day 42 must be positive
            self.add_rule(
                field='hp_malaria_md42_hosp_days',
                validation_func=lambda x: int(x) >= 1 if x and str(x).strip() else True,
                error_msg='Hospitalization days must be at least 1',
                suggestion='Enter a positive number of days',
                severity='Warning'
            )
            
            # Rule 799: Diabetes at Day 42 must be valid
            self.add_rule(
                field='hp_diabetes_md42',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for diabetes',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
            
            # Rule 800: Diabetes hospitalization at Day 42 must be valid
            self.add_rule(
                field='hp_diabetes_md42_hosp',
                validation_func=lambda x: x in ['CH00001', 'CH00002', 'CH00003'] if x and str(x).strip() else True,
                error_msg='Invalid response for diabetes hospitalization',
                suggestion='Select Yes, No, or Unknown',
                severity='Warning'
            )
    
    def fetch_record(self, record_id):
        """Fetch record from REDCap API"""
        # Check if API is configured
        if not self.api_url or not self.api_token or self.api_token == '4DA5AC5A9C3FDA640F4C6F4502C1BAFC':
            print(f"⚠️  Using mock data for record {record_id} (API not configured)")
            return self.get_mock_record(record_id)
        
        # Prepare API request
        payload = {
            'token': self.api_token,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'records[0]': record_id
        }
        
        try:
            print(f"🔍 Fetching record {record_id} from REDCap API...")
            response = requests.post(self.api_url, data=payload)
            response.raise_for_status()
            
            # Check if response is empty
            if not response.text or response.text.strip() == '':
                print(f"⚠️  Empty response from REDCap API for record {record_id}")
                return self.get_mock_record(record_id)
            
            data = response.json()
            if data and len(data) > 0:
                print(f"✅ Successfully fetched record {record_id}")
                return data[0]
            else:
                print(f"⚠️  No data found for record {record_id}")
                return self.get_mock_record(record_id)
                
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection error to REDCap API: {e}")
            print(f"   Make sure REDCap is running at: {self.api_url}")
            return self.get_mock_record(record_id)
        except requests.exceptions.Timeout as e:
            print(f"❌ Timeout connecting to REDCap API: {e}")
            return self.get_mock_record(record_id)
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching record {record_id}: {e}")
            return self.get_mock_record(record_id)
        except ValueError as e:
            print(f"❌ Error parsing JSON response: {e}")
            print(f"   Response text: {response.text[:200]}")
            return self.get_mock_record(record_id)
    
    def get_mock_record(self, record_id):
        """Return mock data for testing when no API token"""
        # This simulates what REDCap would return
        mock_records = {
            'REC-001': {
                'record_id': 'REC-001',
                'age': '25',
                'visit_date': '2026-02-24',
                'email': 'john@example.com',
                'phone': '555-123-4567',
                'quantity': '10',
                'price': '99.99'
            },
            'REC-002': {
                'record_id': 'REC-002',
                'age': '150',  # This will trigger error
                'visit_date': '2026-03-01',  # Future date - error
                'email': 'invalid-email',  # Error
                'phone': '12345',  # Error
                'quantity': '-5',  # Error
                'price': '-10.00'  # Error
            }
        }
        return mock_records.get(record_id, {
            'record_id': record_id,
            'age': '45',
            'visit_date': '2026-02-20',
            'email': 'test@example.com',
            'phone': '555-555-5555',
            'quantity': '5',
            'price': '50.00'
        })
    
    def fetch_user_info(self, record_id, timestamp=None):
        """Get user who entered the data from REDCap logs"""
        if not self.api_token or self.api_token == '4DA5AC5A9C3FDA640F4C6F4502C1BAFC':
            # Return mock user for testing
            return {
                'username': 'test_user',
                'device': 'Web Browser',
                'location': 'Test Location'
            }
        
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        # Parse timestamp if it's a string
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        payload = {
            'token': self.api_token,
            'content': 'log',
            'action': 'export',
            'format': 'json',
            'record': record_id,
            'logtype': 'record',
            'beginTime': (timestamp - timedelta(minutes=30)).isoformat(),
            'endTime': (timestamp + timedelta(minutes=30)).isoformat()
        }
        
        try:
            response = requests.post(self.api_url, data=payload)
            response.raise_for_status()
            logs = response.json()
            
            # Find the most recent relevant log
            for log in logs:
                if log.get('action') in ['Insert', 'Update']:
                    return {
                        'username': log.get('user', 'Unknown'),
                        'device': 'REDCap Web',
                        'location': '',
                        'timestamp': log.get('timestamp', '')
                    }
        except Exception as e:
            print(f"Error fetching user info: {e}")
        
        return {'username': 'Unknown', 'device': 'REDCap Web', 'location': ''}
    
    def validate_record(self, record_id, timestamp=None, form_name=None):
        """Validate a single record against all rules"""
        # Fetch the record
        record = self.fetch_record(record_id)
        if not record:
            print(f"⚠️  No record found for ID: {record_id}")
            return []
        
        # Get user info
        user_info = self.fetch_user_info(record_id, timestamp)
        
        errors = []
        for rule in self.rules:
            field = rule['field']
            
            # Only validate fields that belong to this form
            # You'll need to add a 'form' field to each rule
            if form_name and rule.get('form') and rule['form'] != form_name:
                continue
                
            if field in record:
                value = record[field]
                # Skip empty values
                if value is None or value == '':
                    continue
                    
                try:
                    # Apply validation rule
                    if not rule['func'](value):
                        error = {
                            'record_id': record_id,
                            'field_name': field,
                            'error_value': str(value),
                            'error_message': rule['error_msg'],
                            'suggested_correction': rule['suggestion'],
                            'entered_by': user_info.get('username', 'Unknown'),
                            'device_info': {
                                'device': user_info.get('device', 'Unknown'),
                                'location': user_info.get('location', '')
                            },
                            'severity': rule.get('severity', 'Warning'),
                            'status': 'Pending',
                            'timestamp': datetime.now().isoformat(),
                            'form_name': form_name  # Add form name to error
                        }
                        errors.append(error)
                        print(f"✅ Found error: {field} = '{value}' - {rule['error_msg']}")
                except Exception as e:
                    print(f"⚠️  Error validating {field}: {e}")
        
        return errors
    
    def validate_multiple_records(self, record_ids):
        """Validate multiple records at once"""
        all_errors = []
        for record_id in record_ids:
            errors = self.validate_record(record_id)
            all_errors.extend(errors)
        return all_errors