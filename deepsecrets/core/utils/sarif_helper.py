import sarif_om as om

MAX_LINE_LENGTH_FOR_CONTEXT = 300


class SarifHelper:

    @classmethod
    def get_context_region_for_finding(cls, finding: 'Finding', masking: bool =True):

        start_column = finding.file.get_column_number(position=finding.start_pos) 
        end_column = finding.file.get_column_number(position=finding.end_pos)

        boundaries = cls._get_context_boundaries(finding, start_column, end_column)
        snippet = finding.full_line[boundaries[0]: boundaries[1]]

        if masking:
            snippet = cls._mask(snippet=snippet, detection=finding.detection)
        
        return om.Region(
                start_line=finding.linum,
                start_column=boundaries[0],
                end_column=boundaries[1],
                snippet=om.ArtifactContent(text=snippet)
            )
    

    @classmethod
    def get_region_for_finding(cls, finding: 'Finding', masking: bool =True):

        start_column = finding.file.get_column_number(position=finding.start_pos) 
        end_column = finding.file.get_column_number(position=finding.end_pos)

        snippet = finding.detection

        if masking:
            snippet = cls._mask(snippet=snippet, detection=finding.detection)

        return om.Region(
            start_line=finding.linum,
            end_line=finding.linum,
            start_column=start_column,
            end_column=end_column,
            snippet=om.ArtifactContent(text=snippet)
        )


    @classmethod
    def _get_context_boundaries(self, finding: 'Finding', start_column: int, end_column: int):
        line_length = len(finding.full_line)
        boundaries = [0, line_length]

        if start_column > MAX_LINE_LENGTH_FOR_CONTEXT:
            boundaries[0] = int(start_column - MAX_LINE_LENGTH_FOR_CONTEXT / 2)
            remaining_line = line_length-end_column
            boundaries[1] = int(end_column + (MAX_LINE_LENGTH_FOR_CONTEXT / 2 - remaining_line))

        return boundaries


    @classmethod
    def _mask(cls, snippet: str, detection: str):
        masked_detection = '*'*len(detection)
        return snippet.replace(detection, masked_detection)
    

from deepsecrets.core.model.finding import Finding
